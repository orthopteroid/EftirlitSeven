// eftirlit7 (gpl2) - orthopteroid@gmail.com
// forked from douane-lkms (gpl2) - zedtux@zedroot.org

#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/version.h>        // Needed for LINUX_VERSION_CODE >= KERNEL_VERSION

#include <linux/netdevice.h>       // net_device
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

#include <linux/timekeeping.h>

#include "module.h"
#include "types.h"
#include "netfilter.h"
#include "ksc.h"
#include "asc.h"
#include "rules.h"
#include "netlink.h"
#include "defs.h"

#include "prot_udp.h"
#include "prot_tcp.h"

#ifndef MOD_VERSION
#define MOD_VERSION "UNKNOWN"
#endif

MODULE_DESCRIPTION(MOD_NAME);
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_VERSION(MOD_VERSION);
MODULE_LICENSE("GPL v2");

static time64_t starttime;
static void mod_init_uptime(void)
{
  starttime = ktime_get_seconds();
}
void mod_sample_uptime(void)
{
  def_flag_value[E7F_STAT_UPTIME] = ktime_get_seconds() - starttime;
}

static atomic_t stopping = ATOMIC_INIT(0);

bool mod_isstopping(void)
{
  return atomic_read(&stopping);
}

//////////

static int __init mod_init(void)
{
  LOG_DEBUG(0, "initializing module");

#ifdef DEBUG
  {
    struct net_device *dev = first_net_device(&init_net);
    while(dev)
    {
      LOG_DEBUG(0, "net_device found: name: %s - ifindex: %d", dev->name, dev->ifindex);
      dev = next_net_device(dev);
    }
  }
#endif

  if (def_init() < 0)
  {
    LOG_ERR(0, "def_init failed");
    return -1;
  }

  if (rules_init() < 0)
  {
    LOG_ERR(0, "rules_init failed");
    return -1;
  }

  if (ksc_init() < 0)
  {
    LOG_ERR(0, "ksc_init failed");
    return -1;
  }

  if (asc_init() < 0)
  {
    LOG_ERR(0, "asc_init failed");
    return -1;
  }

  if (prot_udp_init() < 0)
  {
    LOG_ERR(0, "prot_udp_init failed");
    return -1;
  }
  if (prot_tcp_init() < 0)
  {
    LOG_ERR(0, "prot_tcp_init failed");
    return -1;
  }

  if (enl_init() < 0)
  {
    LOG_ERR(0, "enl_init failed");
    return -1;
  }

  if (enf_init() < 0)
  {
    LOG_ERR(0, "enf_init failed");
    return -1;
  }

  mod_init_uptime();
  return 0;
}
module_init(mod_init);

static void __exit mod_exit(void)
{
  // calls that are async or rely on rcu
  enl_send_disconnect(0);

  // set flag and wait until all rcu/softirq processing is done
  // synchronize_rcu waits for a grace period and rcu_barrier waits for all callbacks to complete
  atomic_set(&stopping, 1);
  synchronize_rcu();
  rcu_barrier();

  enf_exit();
  enl_exit();
  ksc_clear(0);
  rules_clear(0);

  prot_udp_exit();
  prot_tcp_exit();

  asc_exit();
  ksc_exit();
  rules_exit();
  def_exit();

  LOG_INFO(0, "module unloaded");
}
module_exit(mod_exit);
