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
#include "types.h"
#include "ksc.h"
#include "asc.h"
#include "rules.h"
#include "prot_udp.h"

bool prot_udp_parse(struct psi *psi_out, uint32_t packet_id, void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct udphdr * udp_header = NULL;
  int sport = 0;
  int dport = 0;

  udp_header = udp_hdr(skb);
  if (udp_header == NULL)
  {
    LOG_ERR(packet_id, "fail - udp_header is null");
    return false;
  }
  sport = (unsigned int) ntohs(udp_header->source);
  dport = (unsigned int) ntohs(udp_header->dest);

  // from packet header and socket buffer try to identify process
  do {
    struct file * socket_file = (skb->sk && skb->sk->sk_socket) ? skb->sk->sk_socket->file : NULL;
    unsigned long socket_ino = socket_file ? file_inode(socket_file)->i_ino : 0;

    {
      bool cache_hit = ksc_from_inode(psi_out, socket_ino, packet_id);
      bool cache_uptodate = cache_hit ? asc_pid_owns_ino(socket_ino, psi_out->pid, packet_id) : false;

      if(cache_uptodate)
      {
        ksc_update_age(socket_ino, packet_id);

        LOG_DEBUG(packet_id, "hit for INODE %ld for PID %d and process '%s'", socket_ino, psi_out->pid, psi_out->process_path);
        break;
      }

      if(asc_psi_from_ino_pid(psi_out, socket_ino, current->pid, packet_id)) ; // no need for message
      else if(asc_psi_from_ino(psi_out, socket_ino, packet_id)) ; // no need for message
      else
      {
        LOG_DEBUG(packet_id, "fail - unable to locate process for FILE %p INODE %ld", socket_file, socket_ino);
        return false;
      };

      if (!cache_hit)
      {
        ksc_remember(socket_ino, 0, psi_out->pid, psi_out->process_path, packet_id);

        LOG_DEBUG(packet_id, "caching new socket INODE %ld for PID %d and process '%s'", socket_ino, psi_out->pid, psi_out->process_path);
        break;
      }

      ksc_update_all(socket_ino, 0, psi_out->pid, psi_out->process_path, packet_id);

      LOG_DEBUG(packet_id, "all updated for INODE %ld. returning '%s'", socket_ino, psi_out->process_path);
      break;
    }

    // fallback to update only age field
    ksc_update_age(socket_ino, packet_id);

    LOG_DEBUG(packet_id, "age update for INODE %ld. returning '%s'", socket_ino, psi_out->process_path);
  } while(false);

  if (psi_out->process_path[0] == 0)
  {
    LOG_ERR(packet_id, "fail - no process path");
    return false;
  }

  return true;

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

    strcpy(activity->process_path, psi_out->process_path);
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

}

//////////////////

int prot_udp_init(void)
{
  return 0;
}

void prot_udp_exit(void)
{
}
