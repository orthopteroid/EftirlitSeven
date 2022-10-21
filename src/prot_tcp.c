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

// per sock.c
static bool sk_info(struct sock* sk, kuid_t* uid, unsigned long* ino, unsigned int* state)
{
  struct inode* inode = 0;
  bool rc = false;

  read_lock_bh(&sk->sk_callback_lock);
  if( sk->sk_socket )
  {
    inode = SOCK_INODE(sk->sk_socket);
    *uid = inode->i_uid;
    *ino = inode->i_ino;
    *state = sk->sk_state;
    rc = true;
  }
  read_unlock_bh(&sk->sk_callback_lock);

  return rc;
}

// douane: code packet identification logic. e7 added tcp state checking and multiple levels of cache integration.
bool prot_tcp_parse(struct psi *psi_out, uint32_t packet_id, void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct tcphdr * tcp_header = NULL;
  unsigned long socket_ino = 0;
  unsigned int tcp_state = 0;
  kuid_t uid;
  uid.val = 0;

  tcp_header = tcp_hdr(skb);
  if (tcp_header == NULL)
  {
    LOG_ERR(packet_id, "fail - tcp_header is null");
    return false;
  }

  // from packet header and socket buffer try to identify process
  do
  {
    bool info = sk_info( skb->sk, &uid, &socket_ino, &tcp_state );

    // ? use sock_hold/_put on skb->sk ?
    // https://github.com/torvalds/linux/blob/v5.8/drivers/crypto/chelsio/chtls/chtls_cm.c#L1488

    if (!info)
    {
      LOG_ERR(packet_id, "fail - unable to identify INODE for skb %p", skb);
      return false;
    }

    {
      bool closing = (tcp_state == TCP_FIN_WAIT1) || (tcp_state == TCP_FIN_WAIT2) || (tcp_state == TCP_CLOSE) || (tcp_state == TCP_CLOSE_WAIT) || (tcp_state == TCP_LAST_ACK) || (tcp_state == TCP_CLOSING);
      bool cache_hit = ksc_from_inode(psi_out, socket_ino, packet_id);
      bool cache_uptodate = cache_hit ? asc_pid_owns_ino(socket_ino, psi_out->pid, packet_id) : false;

      if( !cache_hit && closing )
      {
        LOG_DEBUG(packet_id, "unidentified closed/closing socket for INODE %ld process '%s'", socket_ino, psi_out->process_path);
        break;
      }

      if( cache_uptodate || closing )
      {
        LOG_DEBUG(packet_id, "hit for INODE %ld for PID %d and process '%s'", socket_ino, psi_out->pid, psi_out->process_path);

        ksc_update_age(socket_ino, packet_id);

        LOG_DEBUG(packet_id, "age update for INODE %ld. returning '%s'", socket_ino, psi_out->process_path);
        break;
      }

      // dig deeper to find psi
      if(asc_psi_from_ino_pid(psi_out, socket_ino, current->pid, packet_id)) ; // no need for message
      else if(asc_psi_from_ino(psi_out, socket_ino, packet_id)) ; // no need for message
      else
      {
        LOG_ERR(packet_id, "fail - unable to locate process for INODE %ld", socket_ino);
        return false;
      };

      if (cache_hit)
      {
        ksc_update_all(socket_ino, 0 /* todo: remove */, psi_out->pid, psi_out->process_path, packet_id);

        LOG_DEBUG(packet_id, "all updated for INODE %ld. returning '%s'", socket_ino, psi_out->process_path);
      }
      else
      {
        ksc_remember(socket_ino, 0 /* todo: remove */, psi_out->pid, psi_out->process_path, packet_id);

        LOG_DEBUG(packet_id, "caching new socket INODE %ld for PID %d and process '%s'", socket_ino, psi_out->pid, psi_out->process_path);
      }
    }
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
