// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

// all logic in this file comes from https://gitlab.com/douaneapp/douane-dkms
// code-factoring and new bugs from orthopteroid@gmail.com

#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/version.h>        // Needed for LINUX_VERSION_CODE >= KERNEL_VERSION

#include <linux/netdevice.h>	    // net_device
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
#include "rules.h"
#include "module.h"

// queueable wrapper for kfree_rcu
struct douane_rule_rcu
{
  struct douane_rule r;
  //
  struct list_head  list;
  struct rcu_head   rcu;
};

DEFINE_SPINLOCK(rules_lock);
LIST_HEAD(rules_list);

void rules_print(const uint32_t packet_id)
{
  struct douane_rule_rcu * rule;

  rcu_read_lock();
  list_for_each_entry_rcu(rule, &rules_list, list)
  {
    LOG_DEBUG(0, (rule->r.allowed ? "allowed %s" : "blocked %s"), rule->r.process_path);
  }
  rcu_read_unlock();
}

void rules_append(const char * process_path, const bool is_allowed, const uint32_t packet_id)
{
  struct douane_rule_rcu * rule;

  if (process_path == NULL)
  {
    LOG_ERR(0, "process_path is null");
    return;
  }

  if (strlen(process_path) > PATH_LENGTH)
  {
    LOG_ERR(0, "process_path too long");
    return;
  }

  rule = (struct douane_rule_rcu *)kzalloc(sizeof(struct douane_rule_rcu), GFP_ATOMIC);
  if(rule == NULL)
  {
    LOG_ERR(0, "kzmalloc failed");
    return;
  }

  strncpy(rule->r.process_path, process_path, PATH_LENGTH);
  rule->r.allowed = is_allowed;

  spin_lock(&rules_lock);
  rcu_read_lock();
  list_add_tail_rcu(&rule->list, &rules_list);
  rcu_read_unlock();
  spin_unlock(&rules_lock);

  LOG_DEBUG(0, (rule->r.allowed ? "allowed %s" : "blocked %s"), rule->r.process_path);
}

void rules_clear(const uint32_t packet_id)
{
  struct douane_rule_rcu * rule;
  int rule_cleaned_records = 0;

  if (list_empty(&rules_list))
  {
    LOG_DEBUG(0, "rules_list empty");
    return;
  }

  spin_lock(&rules_lock);
  rcu_read_lock();
  list_for_each_entry_rcu(rule, &rules_list, list)
  {
    list_del_rcu(&rule->list);
    kfree_rcu(rule, rcu);

    rule_cleaned_records++;
  }
  rcu_read_unlock();
  spin_unlock(&rules_lock);

  LOG_DEBUG(0, "%d rule(s) successfully cleaned", rule_cleaned_records);
}

void rules_remove(const unsigned char * process_path, const uint32_t packet_id)
{
  struct douane_rule_rcu * rule;

  if (process_path == NULL)
  {
    LOG_ERR(0, "process_path is null");
    return;
  }

  if (strlen(process_path) > PATH_LENGTH)
  {
    LOG_ERR(0, "process_path too long");
    return;
  }

  spin_lock(&rules_lock);
  rcu_read_lock();
  list_for_each_entry_rcu(rule, &rules_list, list)
  {
    if (strncmp(rule->r.process_path, process_path, PATH_LENGTH) == 0)
    {
      list_del_rcu(&rule->list);
      rcu_read_unlock();
      spin_unlock(&rules_lock);

      kfree_rcu(rule, rcu);

      LOG_DEBUG(0, "deleted rule for %s", process_path);
      return;
    }
  }
  rcu_read_unlock();
  spin_unlock(&rules_lock);

  LOG_DEBUG(0, "no rule to delete for %s", process_path);
}

int rules_search(struct douane_rule * rule_out, const unsigned char * process_path, const uint32_t packet_id)
{
  struct douane_rule_rcu * rule;

  if (process_path == NULL)
  {
    LOG_ERR(0, "process_path is null");
    return -1;
  }

  if (strlen(process_path) > PATH_LENGTH)
  {
    LOG_ERR(0, "process_path too long");
    return -1;
  }

  rcu_read_lock();
  list_for_each_entry_rcu(rule, &rules_list, list)
  {
    if (strncmp(rule->r.process_path, process_path, PATH_LENGTH) == 0)
    {
      LOG_DEBUG(0, (rule->r.allowed ? "found allowed %s" : "found blocked %s"), rule->r.process_path);
      memcpy(rule_out, &rule->r, sizeof(struct douane_rule));

      rcu_read_unlock();
      return 0;
    }
  }
  rcu_read_unlock();

  LOG_DEBUG(packet_id, "rule not found for %s", process_path);
  return -1;
}
