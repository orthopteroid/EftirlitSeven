// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

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

#include "module.h"
#include "douane.h"
#include "psi.h"
#include "pi.h"
#include "rules.h"
#include "netlink.h"

#ifndef MOD_VERSION
#define MOD_VERSION "UNKNOWN"
#endif

MODULE_DESCRIPTION(MOD_NAME);
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_VERSION(MOD_VERSION);
MODULE_LICENSE("GPL v2");

static atomic_t stopping = ATOMIC_INIT(0);

bool mod_isstopping(void)
{
  return atomic_read(&stopping);
}

//////////

void mod_rule_add(const struct rule_struct * rule, const uint32_t stack_id)
{
  rules_append(rule->process_path, rule->allowed, stack_id);
}

void mod_rules_query(const uint32_t stack_id)
{
  struct ruleset_struct_rcu * ruleset = 0;

  if(0>rules_get(&ruleset, stack_id))
  {
    LOG_ERR(stack_id, "rules_get failure");
    return;
  }

  enl_send_rules(ruleset->count, ruleset->rules, stack_id);

  kfree_rcu(ruleset, rcu);
}

void mod_send_echo(const char * message, const uint32_t stack_id)
{
  if(0>enl_send_echo(message, stack_id))
  {
    LOG_ERR(stack_id, "enl_send_echo failure");
    return;
  }
}

struct enl_recvfns mod_recvfns =
{
  .recv_echo = mod_send_echo,
  .enable_set = douane_enable_set,
  .enable_get = douane_enable_get,
  .logging_set = douane_logging_set,
  .logging_get = douane_logging_get,
  .rule_add = mod_rule_add,
  .rules_clear = rules_clear,
  .rules_query = mod_rules_query,
};

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

  if (psi_init() < 0)
  {
    LOG_ERR(0, "psi_init failed");
    return -1;
  }

  if (pi_init() < 0)
  {
    LOG_ERR(0, "pi_init failed");
    return -1;
  }

  if (enl_init(&mod_recvfns) < 0)
  {
    LOG_ERR(0, "enl_init failed");
    return -1;
  }

  if (douane_init() < 0)
  {
    LOG_ERR(0, "douane_init failed");
    return -1;
  }

  LOG_INFO(0, "module loaded");
  return 0;
}
module_init(mod_init);

static void __exit mod_exit(void)
{
  // set flag and wait until all rcu/softirq processing is done
  // synchronize_rcu waits for a grace period and rcu_barrier waits for all callbacks to complete
  atomic_set(&stopping, 1);
  synchronize_rcu();
  rcu_barrier();

  douane_exit();
  enl_exit();
  psi_clear(0);
  rules_clear(0);
  psi_exit();
  pi_exit();

  LOG_INFO(0, "module unloaded");
}
module_exit(mod_exit);
