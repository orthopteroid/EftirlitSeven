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

#include "douane_types.h"
#include "psi.h"
#include "rules.h"
#include "module.h"

// queueable wrapper for kfree_rcu
struct douane_nlpacket_rcu
{
  struct douane_nlpacket activity;
  //
  struct rcu_head rcu;
};

// fwd decls
static unsigned int douane_nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
static void douane_nlhandler(struct sk_buff *skb);

static struct nf_hook_ops netfilter_config = {
  .hook     = douane_nfhandler,
  .hooknum  = NF_IP_LOCAL_OUT,
  .pf       = NFPROTO_IPV4,
  .priority = NF_IP_PRI_LAST,
};

static struct netlink_kernel_cfg netlink_config =
{
  .input = douane_nlhandler,
};

DEFINE_SPINLOCK(netlink_lock);
struct sock * daemon_socket = NULL;
pid_t daemon_pid = 0;

static bool enabled = true;
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

void douane_renew_daemon_socket(const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "renewing netlink socket");

  spin_lock(&netlink_lock);
  if (daemon_socket)
    netlink_kernel_release(daemon_socket);
  daemon_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &netlink_config);
  daemon_pid = 0;
  spin_unlock(&netlink_lock);
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

void douane_nlhandler(struct sk_buff *skb)
{
  struct nlmsghdr * nlh = nlmsg_hdr(skb);
  struct douane_nlpacket * activity = NLMSG_DATA(nlh);
  struct douane_rule existing_rule;
  uint32_t packet_id;

  get_random_bytes(&packet_id, sizeof(packet_id));

  if (activity == NULL)
  {
    LOG_ERR(packet_id, "NLMSG_DATA failed");
    return;
  }

  switch(activity->kind)
  {
    case KIND_HAND_SHAKE:
      daemon_pid = nlh->nlmsg_pid;
      LOG_DEBUG(packet_id, "process %d registered.", daemon_pid);
      break;

    case KIND_SENDING_RULE:
      if (rules_search(&existing_rule, activity->process_path, packet_id) < 0)
      {
        rules_append(activity->process_path, (activity->allowed == 1), packet_id);
      }
      break;

    case KIND_DELETE_RULE:
      rules_remove(activity->process_path, packet_id);
      break;

    case KIND_GOODBYE:
      douane_renew_daemon_socket(packet_id);
      break;

    default:
      LOG_ERR(packet_id, "invalid message");
      douane_renew_daemon_socket(packet_id);
      psi_clear(packet_id);
      rules_clear(packet_id);
  }
}

static bool douane_match_ino_to_pid(unsigned long socket_ino, pid_t pid, const uint32_t packet_id)
{
  struct file * file;
  int fd_i, fd_null, fd_null_max;
  const int MAX_FD_NULL = 9;

  /*
  ** In order to avoid going through all the fds of a process
  *  the fd_null variable is used to define a limit.
  *  This allows Douane to ignore processes which aren't owning the fd
  *  and switch to the next process, so Douane is faster.
  *
  *  But this limit can make Douane blind and will never find the process.
  *  In order to highligh this, the fd_null_max variable, which is printed
  *  in the logs in debug mode, shows the correct number for the current
  *  process.
  *
  *  For example, with Ubuntu <= 13.10, the correct value for fd_null is 3,
  *  while now with Ubuntu 14.04, the correct value for fd_null is around 8.
  */

  rcu_read_lock();

  {
    struct pid * pid_struct = find_get_pid(pid);
    struct task_struct * task = pid_struct ? get_pid_task(pid_struct, PIDTYPE_PID) : NULL;

    if (task && task->files)
    {
      fd_i = -1;
      fd_null = 0;
      fd_null_max = 0;

      while (fd_null < MAX_FD_NULL)
      {
        fd_i++;
        file = fcheck_files(task->files, fd_i);
        if (!file) { if (++fd_null > fd_null_max) fd_null_max = fd_null; continue; } // no file for this handle, inc heuristic count
        if (!S_ISSOCK(file_inode(file)->i_mode)) continue; // not a socket file
        if (file_inode(file)->i_ino != socket_ino) continue;

        goto out_found;
      }
    }
  }

  rcu_read_unlock();
  LOG_ERR(packet_id, "task not found for INO %ld", socket_ino);
  return false;

out_found:
  rcu_read_unlock();
  LOG_DEBUG(packet_id, "task found for INO %ld", socket_ino);
  return true;
}

static bool douane_lookup_skfile(struct douane_psi * psi_out, struct file * socket_file, const uint32_t packet_id)
{
  struct file * file;
  int fd_i, fd_null, fd_null_max;
  const int MAX_FD_NULL = 9;
  struct task_struct * task;
  int name_str_len;
  char * p;
  //
  char * deleted_str = " (deleted)";
  int deleted_str_len = 10;

  /*
  ** In order to avoid going through all the fds of a process
  *  the fd_null variable is used to define a limit.
  *  This allows Douane to ignore processes which aren't owning the fd
  *  and switch to the next process, so Douane is faster.
  *
  *  But this limit can make Douane blind and will never find the process.
  *  In order to highligh this, the fd_null_max variable, which is printed
  *  in the logs in debug mode, shows the correct number for the current
  *  process.
  *
  *  For example, with Ubuntu <= 13.10, the correct value for fd_null is 3,
  *  while now with Ubuntu 14.04, the correct value for fd_null is around 8.
  */

  rcu_read_lock();

  for_each_process(task)
  {
    if (task->files == NULL) continue; // this task has no files open

    fd_i = -1;
    fd_null = 0;
    fd_null_max = 0;

    while (fd_null < MAX_FD_NULL)
    {
      fd_i++;
      file = fcheck_files(task->files, fd_i);
      if (!file) { if (++fd_null > fd_null_max) fd_null_max = fd_null; continue; } // no file for this handle, inc heuristic count
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

      LOG_DEBUG(packet_id, "fd_null_max: %d | MAX_FD_NULL: %d", fd_null_max, MAX_FD_NULL);
      goto out_found;
    }

  }
  LOG_ERR(packet_id, "fd_null_max: %d | MAX_FD_NULL: %d", fd_null_max, MAX_FD_NULL);

out_fail:
  rcu_read_unlock();
  return false;

out_found:
  psi_out->pid = task->pid;
  if(psi_out->process_path != p)
  {
    // start of string is not start of buffer, so strip prefix
    strncpy(psi_out->process_path, p, PATH_LENGTH - (p - psi_out->process_path) +1); // +1 includes \0

    LOG_DEBUG(packet_id, "stripped prefix: %s", psi_out->process_path);
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

      LOG_DEBUG(packet_id, "stripped suffix: %s", psi_out->process_path);
    }
  }
  return true;
}


static bool douane_lookup_skbuffer(const struct sk_buff * skb, const struct tcphdr * tcp_header, struct douane_psi *psi_out, bool * filterable, const uint32_t packet_id)
{
  struct file * socket_file = (skb->sk && skb->sk->sk_socket) ? skb->sk->sk_socket->file : NULL;
  unsigned long socket_ino = socket_file ? file_inode(socket_file)->i_ino : 0;
  uint32_t tcp_seq = tcp_header ? ntohl(tcp_header->seq) : 0;

  // ? use sock_hold/_put on skb->sk ?
  // https://github.com/torvalds/linux/blob/v5.8/drivers/crypto/chelsio/chtls/chtls_cm.c#L1488

  if (!socket_file)
  {
    bool found_using_tcpseq = tcp_header ? psi_from_sequence(psi_out, tcp_seq, packet_id) : false;
    if (!found_using_tcpseq)
    {
      LOG_ERR(packet_id, "missing header or bad seq. unable to identify socket");
      return false;
    }

    LOG_DEBUG(packet_id, "process '%s' identified from tcp_seq", psi_out->process_path);
    return true;
  }

  *filterable = true;

  {
    bool cache_hit = socket_ino ? psi_from_inode(psi_out, socket_ino, packet_id) : false;
    if (!cache_hit)
    {
      if (!douane_lookup_skfile(psi_out, socket_file, packet_id))
      {
        LOG_ERR(packet_id, "unable to identify process for FILE %p INODE %ld", socket_file, socket_ino);
        return false;
      }

      psi_remember(socket_ino, tcp_seq, psi_out->pid, psi_out->process_path, packet_id);

      LOG_DEBUG(packet_id, "caching new socket INODE %ld SEQ %u for PID %d. returning '%s'", socket_ino, tcp_seq, psi_out->pid, psi_out->process_path);
      return true;
    }
  }

  if (!douane_match_ino_to_pid(socket_ino, psi_out->pid, packet_id))
  {
    psi_update_all(socket_ino, tcp_seq, psi_out->pid, psi_out->process_path, packet_id);

    LOG_DEBUG(packet_id, "all updated for INODE %ld. returning '%s'", socket_ino, psi_out->process_path);
    return true;
  }

  if (tcp_header)
  {
    psi_update_seq(socket_ino, tcp_seq, packet_id);

    LOG_DEBUG(packet_id, "seq update for INODE %ld to SEQ %u. returning '%s'", socket_ino, tcp_seq, psi_out->process_path);
    return true;
  }

  psi_update_age(socket_ino, packet_id);

  LOG_DEBUG(packet_id, "age update for INODE %ld. returning '%s'", socket_ino, psi_out->process_path);
  return true;
}

static int douane_send_nlpacket(const struct douane_nlpacket * activity, const uint32_t packet_id)
{
  struct nlmsghdr * nlh;
  struct sk_buff *  skb = NULL;
  int               ret = 0;

  if (daemon_socket == NULL)
  {
    LOG_ERR(packet_id, "BLOCKED PUSH: Socket not connected!!");
    return -1;
  }

  if (activity->process_path == NULL || strcmp(activity->process_path, "") == 0)
  {
    LOG_ERR(packet_id, "BLOCKED PUSH: process_path is blank");
    return 0;
  }

  if (strlen(activity->process_path) > PATH_LENGTH)
  {
    LOG_ERR(packet_id, "BLOCKED PUSH: process_path is too long");
  }

  // Create a new netlink message
  skb = nlmsg_new(NLMSG_ALIGN(sizeof(struct douane_nlpacket)) + nla_total_size(1), GFP_KERNEL);
  if (skb == NULL)
  {
    LOG_ERR(packet_id, "BLOCKED PUSH: Failed to allocate new socket buffer");
    return -1;
  }

  // Add a netlink message to an skb
  nlh = nlmsg_put(skb, 0, 0, NLMSG_DONE, sizeof(struct douane_nlpacket), 0);
  if (nlh == NULL)
  {
    if (skb)
    {
      kfree_skb(skb);
    }
    LOG_ERR(packet_id, "BLOCKED PUSH: nlmsg_put failed");
    return -1;
  }

  NETLINK_CB(skb).portid = 0; /* from kernel */
  memcpy(NLMSG_DATA(nlh), activity, sizeof(struct douane_nlpacket));

  nlh->nlmsg_flags = NLM_F_REQUEST; // Must be set on all request messages.

  // Unicast a message to a single socket
  // netlink_unicast() takes ownership of the skb and frees it itself.
  spin_lock(&netlink_lock);
  if(daemon_socket)
  {
    ret = netlink_unicast(daemon_socket, skb, daemon_pid, MSG_DONTWAIT);
  }
  spin_unlock(&netlink_lock);

  if (ret < 0)
  {
    if (ret == -11)
    {
      LOG_ERR(packet_id, "Message ignored as Netfiler socket is busy");
    }
    else
    {
      LOG_ERR(packet_id, "Failed to send message (errno: %d)", ret);
      // No more try to push rules to the daemon
      daemon_pid = 0;
    }
    return ret;
  }
  else
  {
    return 0;
  }
}

static unsigned int douane_nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr *                ip_header = NULL;
  struct udphdr *               udp_header = NULL;
  struct tcphdr *               tcp_header = NULL;
  struct douane_rule existing_rule;
  int                           sport = 0;
  int                           dport = 0;
  bool                          filterable = false;
  struct douane_psi psi;
  uint32_t                      packet_id;

  memset(&psi, 0, sizeof(struct douane_psi));

  get_random_bytes(&packet_id, sizeof(packet_id));

  LOG_DEBUG(packet_id, "~~~ new packet");

  if (mod_isstopping())
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (module is stopping)");
    return NF_ACCEPT;
  }

  if (enabled == false)
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (all filtering is disabled)");
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
      return NF_ACCEPT;
  }

  if (!douane_lookup_skbuffer(skb, tcp_header, &psi, &filterable, packet_id))
  {
    LOG_DEBUG(packet_id, "douane_lookup_skbuffer failed");
  }

  if (filterable && (psi.process_path[0] == 0))
  {
    LOG_ERR(packet_id, "psi.process_path is blank but was filterable");
    LOG_DEBUG(packet_id, "NF_ACCEPT (no process path)");
    return NF_ACCEPT;
  }

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
  spin_lock(&netlink_lock);
  daemon_socket = netlink_kernel_create(&init_net, NETLINK_USERSOCK, &netlink_config);
  daemon_pid = 0;
  spin_unlock(&netlink_lock);

  if (daemon_socket == NULL)
  {
    LOG_ERR(0, "netlink_kernel_create failed");
    return -1;
  }

  nf_register_net_hook(&init_net, &netfilter_config);

  return 0;
}

void douane_exit(void)
{
  nf_unregister_net_hook(&init_net, &netfilter_config);

  spin_lock(&netlink_lock);
  if (daemon_socket)
    netlink_kernel_release(daemon_socket);
  daemon_socket = NULL;
  daemon_pid = 0;
  spin_unlock(&netlink_lock);
}
