// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

// all logic in this file comes from https://gitlab.com/douaneapp/douane-dkms
// code-factoring and new bugs from orthopteroid@gmail.com

#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/version.h>        // Needed for LINUX_VERSION_CODE >= KERNEL_VERSION
// ~~~~ Due to bug https://bugs.launchpad.net/ubuntu/+source/linux/+bug/929715 ~~~~
// #undef __KERNEL__
// #include <linux/netfilter_ipv4.h> // NF_IP_POST_ROUTING, NF_IP_PRI_LAST
// #define __KERNEL__
#define NF_IP_LOCAL_OUT 3
enum nf_ip_hook_priorities {
  NF_IP_PRI_LAST = INT_MAX
};
// ~~~~
#include <linux/netdevice.h>      // net_device
#include <linux/netfilter.h>      // nf_register_hook(), nf_unregister_hook(), nf_register_net_hook(), nf_unregister_net_hook()
#include <linux/netlink.h>        // NLMSG_SPACE(), nlmsg_put(), NETLINK_CB(), NLMSG_DATA(), NLM_F_REQUEST, netlink_unicast(), netlink_kernel_release(), nlmsg_hdr(), NETLINK_USERSOCK, netlink_kernel_create()

#include <linux/sched/signal.h>          // for_each_process(), task_lock(), task_unlock()

#include <linux/ip.h>             // ip_hdr()
#include <linux/udp.h>            // udp_hdr()
#include <linux/tcp.h>            // tcp_hdr()
#include <linux/fdtable.h>        // files_fdtable(), fcheck_files()
#include <linux/list.h>           // INIT_LIST_HEAD(), list_for_each_entry(), list_add_tail(), list_empty(), list_entry(), list_del(), list_for_each_entry_safe()
#include <linux/dcache.h>         // d_path()
#include <linux/skbuff.h>         // alloc_skb()
#include <linux/pid_namespace.h>  // task_active_pid_ns()
#include <linux/rculist.h>        // hlist_for_each_entry_rcu

#include "module.h"
#include "psi.h"
#include "rules.h"

// fwd decls
static unsigned int douane_nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct nf_hook_ops netfilter_config = {
  .hook     = douane_nfhandler,
  .hooknum  = NF_IP_LOCAL_OUT,
  .pf       = NFPROTO_IPV4,
  .priority = NF_IP_PRI_LAST,
};

static bool enabled = false;
static bool logging = true;

///////////////

void douane_enable_set(bool value, const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "enable change to %s", value ? "enable" : "disable");

  enabled = value;
}

void douane_enable_get(bool * value_out, const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "get enable value of %s", enabled ? "enable" : "disable");

  *value_out = enabled;
}

void douane_logging_set(bool value, const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "logging change to %s", value ? "enable" : "disable");

  logging = value;
}

void douane_logging_get(bool * value_out, const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "get logging value of %s", logging ? "enable" : "disable");

  *value_out = logging;
}

char * douane_lookup_protname(const int protocol)
{
  switch(protocol)
  {
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_IGMP: return "IGMP";
    case IPPROTO_IPIP: return "IPIP";
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_EGP: return "EGP";
    case IPPROTO_PUP: return "PUP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_IDP: return "IDP";
    case IPPROTO_TP: return "TP";
    case IPPROTO_DCCP: return "DCCP";
    case IPPROTO_IPV6: return "IPV6";
    case IPPROTO_RSVP: return "RSVP";
    case IPPROTO_GRE: return "GRE";
    case IPPROTO_ESP: return "ESP";
    case IPPROTO_AH: return "AH";
    case IPPROTO_MTP: return "MTP";
    case IPPROTO_BEETPH: return "BEETPH";
    case IPPROTO_ENCAP: return "ENCAP";
    case IPPROTO_PIM: return "PIM";
    case IPPROTO_COMP: return "COMP";
    case IPPROTO_SCTP: return "SCTP";
    case IPPROTO_UDPLITE: return "UDPLITE";
    case IPPROTO_MPLS: return "MPLS";
    case IPPROTO_RAW: return "RAW";
    default: return "UNKNOWN";
  }
}

///////////////

static bool douane_pid_owns_ino(unsigned long socket_ino, pid_t pid, const uint32_t packet_id)
{
  rcu_read_lock();

  {
    struct pid * pid_struct = find_get_pid(pid);
    struct task_struct * task = pid_struct ? get_pid_task(pid_struct, PIDTYPE_PID) : NULL;

    if (task && task->files)
    {
      unsigned int fd_i = 0;
      unsigned int fd_max = files_fdtable(task->files)->max_fds;
      for(fd_i = 0; fd_i < fd_max; fd_i++)
      {
        struct file * file = fcheck_files(task->files, fd_i);
        if (!file) continue;
        if (!S_ISSOCK(file_inode(file)->i_mode)) continue; // not a socket file
        if (file_inode(file)->i_ino != socket_ino) continue;

        goto out_found;
      }
    }
  }

  rcu_read_unlock();
  LOG_ERR(packet_id, "no match for INO %ld and PID %d", socket_ino, pid);
  return false;

out_found:
  rcu_read_unlock();
  LOG_DEBUG(packet_id, "match found");
  return true;
}

static bool douane_psi_from_skfile(struct psi_struct * psi_out, struct file * socket_file, const uint32_t packet_id)
{
  struct task_struct * task;
  int name_str_len;
  char * p;
  //
  char * deleted_str = " (deleted)";
  int deleted_str_len = 10;

  if(!socket_file)
  {
    LOG_ERR(packet_id, "searching for FILE %p - invalid", socket_file);
    return false;
  }

  rcu_read_lock();

  for_each_process(task)
  {
    if (task->files)
    {
      unsigned int fd_i = 0;
      unsigned int fd_max = files_fdtable(task->files)->max_fds;

      for(fd_i = 0; fd_i < fd_max; fd_i++)
      {
        struct file * file = fcheck_files(task->files, fd_i);
        if (!file) continue;
        if (!S_ISSOCK(file_inode(file)->i_mode)) continue; // not a socket file
        if (file != socket_file) continue; // not MY socket_file!

        if (!likely(task->mm) || !task->mm->exe_file)
        {
          LOG_ERR(packet_id, "invalid task info");
          goto out_fail;
        }

        // notes:
        // - d_path might return string with " (deleted)" suffix
        // - d_path might return string with garbage prefix
        p = d_path(&task->mm->exe_file->f_path, psi_out->process_path, PATH_LENGTH);
        if (IS_ERR(p))
        {
          LOG_ERR(packet_id, "d_path returned ERROR");
          goto out_fail;
        }

        goto out_found;
      }
    }
  }

out_fail:
  LOG_DEBUG(packet_id, "searching for FILE %p - not found", socket_file);

  rcu_read_unlock();
  return false;

out_found:
  LOG_DEBUG(packet_id, "searching for FILE %p - found PID %d", socket_file, task->pid);

  psi_out->pid = task->pid;
  if(psi_out->process_path != p)
  {
    // start of string is not start of buffer, so strip prefix
    strncpy(psi_out->process_path, p, PATH_LENGTH - (p - psi_out->process_path) +1); // +1 includes \0
  }

  rcu_read_unlock();

  // check for " (deleted)" suffix and strip it
  name_str_len = strnlen(psi_out->process_path, PATH_LENGTH);
  if (name_str_len > deleted_str_len)
  {
    // long enough for a suffix
    int suffix_position = name_str_len - deleted_str_len;
    if (0 == strncmp(psi_out->process_path + suffix_position, deleted_str, deleted_str_len))
    {
      memset(psi_out->process_path + suffix_position, 0, deleted_str_len);
    }
  }
  return true;
}


static unsigned int douane_nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr * ip_header = NULL;
  struct udphdr * udp_header = NULL;
  struct tcphdr * tcp_header = NULL;
  struct rule_struct existing_rule;
  int sport = 0;
  int dport = 0;
  bool filterable = false;
  struct psi_struct psi;
  uint32_t packet_id;

  memset(&psi, 0, sizeof(struct psi_struct));

  get_random_bytes(&packet_id, sizeof(packet_id));

  LOG_DEBUG(packet_id, "~~~ new packet");

  if (mod_isstopping())
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (module is stopping)");
    return NF_ACCEPT;
  }

  if (skb == NULL)
  {
    LOG_ERR(packet_id, "NF_ACCEPT (socket buffer is null)");
    return NF_ACCEPT;
  }

  ip_header = ip_hdr(skb);
  if (ip_header == NULL)
  {
    LOG_ERR(packet_id, "NF_ACCEPT (ip_header is null)");
    return NF_ACCEPT;
  }
  LOG_DEBUG(packet_id, "packet %s, %s",
    douane_lookup_protname(ip_header->protocol),
    in_softirq() ? "in_softirq()" : "!in_softirq()"
  );

  switch(ip_header->protocol)
  {
    case IPPROTO_UDP:
      udp_header = udp_hdr(skb);
      if (udp_header == NULL)
      {
        LOG_ERR(packet_id, "NF_ACCEPT (udp_header is null)");
        return NF_ACCEPT;
      }
      sport = (unsigned int) ntohs(udp_header->source);
      dport = (unsigned int) ntohs(udp_header->dest);
      break;

    case IPPROTO_TCP:
      tcp_header = tcp_hdr(skb);
      if (tcp_header == NULL)
      {
        LOG_ERR(packet_id, "NF_ACCEPT (tcp_header is null)");
        return NF_ACCEPT;
      }
      sport = (unsigned int) ntohs(tcp_header->source);
      dport = (unsigned int) ntohs(tcp_header->dest);
      break;

    default:
      LOG_ERR(packet_id, "NF_ACCEPT (ip_header->protocol fallthrough)");
      return NF_ACCEPT;
  }

  // from packet header and socket buffer try to identify process
  do {
    struct file * socket_file = (skb->sk && skb->sk->sk_socket) ? skb->sk->sk_socket->file : NULL;
    unsigned long socket_ino = socket_file ? file_inode(socket_file)->i_ino : 0;
    uint32_t tcp_seq = tcp_header ? ntohl(tcp_header->seq) : 0;

    // ? use sock_hold/_put on skb->sk ?
    // https://github.com/torvalds/linux/blob/v5.8/drivers/crypto/chelsio/chtls/chtls_cm.c#L1488

    if (!socket_file)
    {
      bool found_using_tcpseq = tcp_header ? psi_from_sequence(&psi, tcp_seq, packet_id) : false;
      if (!found_using_tcpseq)
      {
        LOG_ERR(packet_id, "NF_ACCEPT (missing header or bad seq. unable to identify socket for process '%s')", psi.process_path);
        return NF_ACCEPT;
      }
    }

    filterable = true;

    {
      bool psi_cache_hit = socket_ino ? psi_from_inode(&psi, socket_ino, packet_id) : false;
      bool ino_pid_match = psi_cache_hit ? douane_pid_owns_ino(socket_ino, psi.pid, packet_id) : false;

      if (psi_cache_hit && ino_pid_match)
      {
        psi_update_age(socket_ino, packet_id);

        LOG_DEBUG(packet_id, "hit for INODE %ld SEQ %u for PID %d and process '%s'", socket_ino, tcp_seq, psi.pid, psi.process_path);
        break;
      }

      if (!douane_psi_from_skfile(&psi, socket_file, packet_id))
      {
        unsigned int tcp_state = (skb->sk && skb->sk) ? skb->sk->sk_state : 0; // 0 invalid
        do {
          if(tcp_state == TCP_FIN_WAIT1) break;
          if(tcp_state == TCP_FIN_WAIT2) break;
          if(tcp_state == TCP_CLOSE) break;
          if(tcp_state == TCP_CLOSE_WAIT) break;
          if(tcp_state == TCP_CLOSING) break;

          LOG_ERR(packet_id, "NF_ACCEPT (unable to identify process for FILE %p INODE %ld)", socket_file, socket_ino);
          return NF_ACCEPT;
        } while(false);

        LOG_DEBUG(packet_id, "NF_ACCEPT (tcp socket shutting down for FILE %p INODE %ld process '%s')", socket_file, socket_ino, psi.process_path);
        return NF_ACCEPT;
      }

      if (!psi_cache_hit)
      {
        psi_remember(socket_ino, tcp_seq, psi.pid, psi.process_path, packet_id);

        LOG_DEBUG(packet_id, "caching new socket INODE %ld SEQ %u for PID %d and process '%s'", socket_ino, tcp_seq, psi.pid, psi.process_path);
        break;
      }

      if (!ino_pid_match)
      {
        psi_update_all(socket_ino, tcp_seq, psi.pid, psi.process_path, packet_id);

        LOG_DEBUG(packet_id, "all updated for INODE %ld. returning '%s'", socket_ino, psi.process_path);
        break;
      }

      LOG_ERR(packet_id, "logic error");
      break;
    }

    if (tcp_seq)
    {
      psi_update_seq(socket_ino, tcp_seq, packet_id);

      LOG_DEBUG(packet_id, "seq update for INODE %ld to SEQ %u. returning '%s'", socket_ino, tcp_seq, psi.process_path);
      break;
    }

    // fallback to update only age field
    psi_update_age(socket_ino, packet_id);

    LOG_DEBUG(packet_id, "age update for INODE %ld. returning '%s'", socket_ino, psi.process_path);
  } while(false);

  if (psi.process_path[0] == 0)
  {
    LOG_ERR(packet_id, "NF_ACCEPT (no process path)");
    return NF_ACCEPT;
  }

/*

#define KIND_HAND_SHAKE   1
#define KIND_SENDING_RULE 2
#define KIND_GOODBYE      3
#define KIND_DELETE_RULE  4

// raw netlink-io packet to douane-daemon
// nb: this revision has smaller process_path so-as to allow kfree_rcu usage
struct douane_nlpacket {
  int   kind;                         // Deamon -> LKM  | Define which kind of message it is
  char  process_path[PATH_LENGTH +1]; // Bidirectional  | Related process path, +1 for \0
  int   allowed;                      // Deamon -> LKM  | Define if the process is allowed to outgoing network traffic or not
  char  device_name[16];              // Bidirectional  | Device name where the packet has been detected (IFNAMSIZ = 16)
  int   protocol;                     // LKM -> Deamon  | Protocol id of the detected outgoing network activity
  char  ip_source[16];                // LKM -> Deamon  | Outgoing network traffic ip source
  int   port_source;                  // LKM -> Deamon  | Outgoing network traffic port source
  char  ip_destination[16];           // LKM -> Deamon  | Outgoing network traffic ip destination
  int   port_destination;             // LKM -> Deamon  | Outgoing network traffic port destination
  int   size;                         // LKM -> Deamon  | Size of the packet
};

  if (daemon_socket == NULL || daemon_pid == 0)
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (no daemon)");
    return NF_ACCEPT;
  }

  {
    struct douane_nlpacket_rcu * activity_rcu = kzalloc(sizeof(struct douane_nlpacket_rcu), GFP_ATOMIC );
    struct douane_nlpacket * activity = activity_rcu ? &activity_rcu->activity : NULL;
    char ip_source[16];
    char ip_destination[16];

    if (activity == NULL)
    {
      LOG_ERR(packet_id, "NF_ACCEPT (kzalloc failed)");
      return NF_ACCEPT;
    }

    snprintf(ip_source, 16, "%pI4", &ip_header->saddr);
    snprintf(ip_destination, 16, "%pI4", &ip_header->daddr);

    strcpy(activity->process_path, psi.process_path);
    strcpy(activity->device_name, state->out->name);
    activity->protocol = ip_header->protocol;
    strcpy(activity->ip_source, ip_source);
    activity->port_source = sport;
    strcpy(activity->ip_destination, ip_destination);
    activity->port_destination = dport;
    activity->size = skb->len;

    // synchronous
    // as we're outside an rculock is this block-safe?
    if (douane_send_nlpacket(activity, packet_id) < 0)
    {
      LOG_ERR(packet_id, "douane_send_nlpacket failed");
    }
    else
    {
      LOG_DEBUG(packet_id, "douane_send_nlpacket completed to PID %d", daemon_pid);
    }

    kfree_rcu(activity_rcu, rcu);
  }
*/

  if (!enabled)
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (filtering disabled. process %s)", psi.process_path);
    return NF_ACCEPT;
  }

  if (filterable)
  {
    LOG_DEBUG(packet_id, "searching rule for %s", psi.process_path);

    if (rules_search(&existing_rule, psi.process_path, packet_id) < 0)
    {
      LOG_DEBUG(packet_id, "NF_QUEUE (rules_search failed for %s)", psi.process_path);
      return NF_QUEUE;
    }
    else
    {
      if (existing_rule.allowed)
      {
        LOG_DEBUG(packet_id, "NF_ACCEPT (allow %s)", psi.process_path);
        return NF_ACCEPT;
      }
      else
      {
        LOG_DEBUG(packet_id, "NF_DROP (block %s)", psi.process_path);
        return NF_DROP;
      }
    }
  }
  else
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (unfilterable %s)", psi.process_path);
    return NF_ACCEPT;
  }
}

//////////////////

int douane_init(void)
{
  nf_register_net_hook(&init_net, &netfilter_config);
  return 0;
}

void douane_exit(void)
{
  nf_unregister_net_hook(&init_net, &netfilter_config);
}
