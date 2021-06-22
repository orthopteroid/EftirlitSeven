// eftirlit7 (gpl2) - orthopteroid@gmail.com
// forked from douane-lkms (gpl2) - zedtux@zedroot.org

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
#include "prot_tcp.h"

// douane: code packet identification logic. e7 added tcp state checking and multiple levels of cache integration.
bool prot_tcp_parse(struct psi *psi_out, uint32_t packet_id, void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct tcphdr * tcp_header = NULL;
  int sport = 0;
  int dport = 0;

  tcp_header = tcp_hdr(skb);
  if (tcp_header == NULL)
  {
    LOG_ERR(packet_id, "fail - tcp_header is null");
    return false;
  }
  sport = (unsigned int) ntohs(tcp_header->source);
  dport = (unsigned int) ntohs(tcp_header->dest);

  // from packet header and socket buffer try to identify process
  do {
    struct file * socket_file = (skb->sk && skb->sk->sk_socket) ? skb->sk->sk_socket->file : NULL;
    unsigned long socket_ino = socket_file ? file_inode(socket_file)->i_ino : 0;
    uint32_t tcp_seq = tcp_header ? ntohl(tcp_header->seq) : 0;

    // ? use sock_hold/_put on skb->sk ?
    // https://github.com/torvalds/linux/blob/v5.8/drivers/crypto/chelsio/chtls/chtls_cm.c#L1488

    if (!socket_file)
    {
      bool tcpseq_cached = tcp_header ? ksc_from_sequence(psi_out, tcp_seq, packet_id) : false;
      //bool tcpseq_lookup = (tcp_seq & !tcpseq_cached) ? asc_psi_from_tcpseq(psi_out, tcp_seq, packet_id) : false; // todo
      if (!tcpseq_cached)
      {
        LOG_ERR(packet_id, "fail - missing header or bad seq. unable to identify socket for process '%s'", psi_out->process_path);
        return false;
      }

      // set ino, if it can be found from seq number
      socket_ino = psi_out->i_ino;
    }

    if (!socket_ino)
    {
      unsigned int tcp_state = (skb->sk && skb->sk) ? skb->sk->sk_state : 0; // 0 invalid
      do {
        if(tcp_state == TCP_FIN_WAIT1) break;
        if(tcp_state == TCP_FIN_WAIT2) break;
        if(tcp_state == TCP_CLOSE) break;
        if(tcp_state == TCP_CLOSE_WAIT) break;
        if(tcp_state == TCP_CLOSING) break;

        LOG_ERR(packet_id, "fail - unidentified tcp socket state. possibly for FILE %p INODE %ld process '%s'", socket_file, socket_ino, psi_out->process_path);
        return false;
      } while(false);

      LOG_DEBUG(packet_id, "fail - closed/closing tcp socket. possibly for FILE %p INODE %ld process '%s'", socket_file, socket_ino, psi_out->process_path);
      return true;
    }

    {
      bool cache_hit = ksc_from_inode(psi_out, socket_ino, packet_id);
      bool cache_uptodate = cache_hit ? asc_pid_owns_ino(socket_ino, psi_out->pid, packet_id) : false;

      if(cache_uptodate)
      {
        ksc_update_age(socket_ino, packet_id);

        LOG_DEBUG(packet_id, "hit for INODE %ld SEQ %u for PID %d and process '%s'", socket_ino, tcp_seq, psi_out->pid, psi_out->process_path);
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
        ksc_remember(socket_ino, tcp_seq, psi_out->pid, psi_out->process_path, packet_id);

        LOG_DEBUG(packet_id, "caching new socket INODE %ld SEQ %u for PID %d and process '%s'", socket_ino, tcp_seq, psi_out->pid, psi_out->process_path);
        break;
      }

      ksc_update_all(socket_ino, tcp_seq, psi_out->pid, psi_out->process_path, packet_id);

      LOG_DEBUG(packet_id, "all updated for INODE %ld. returning '%s'", socket_ino, psi_out->process_path);
      break;
    }

    if (tcp_seq)
    {
      ksc_update_seq(socket_ino, tcp_seq, packet_id);

      LOG_DEBUG(packet_id, "seq update for INODE %ld to SEQ %u. returning '%s'", socket_ino, tcp_seq, psi_out->process_path);
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
}

//////////////////

int prot_tcp_init(void)
{
  return 0;
}

void prot_tcp_exit(void)
{
}
