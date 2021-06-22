// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

// all logic in this file comes from https://gitlab.com/douaneapp/douane-dkms
// code-factoring and new bugs from orthopteroid@gmail.com

#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/version.h>        // Needed for LINUX_VERSION_CODE >= KERNEL_VERSION

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
#include "rules.h"

// queueable wrapper for kfree_rcu
struct rule_struct_rcu
{
  struct rule_struct r;
  //
  struct list_head  list;
  struct rcu_head   rcu;
};

DEFINE_SPINLOCK(rules_lock);
LIST_HEAD(rules_list);

void rules_print(const uint32_t packet_id)
{
  struct rule_struct_rcu * rule;

  rcu_read_lock();
  list_for_each_entry_rcu(rule, &rules_list, list)
  {
    LOG_DEBUG(packet_id, "%s %s", (rule->r.allowed ? "allowed" : "blocked"), rule->r.process_path);
  }
  rcu_read_unlock();
}

int rules_get(struct ruleset_struct_rcu ** ruleset_out_rcufree, const uint32_t packet_id)
{
  struct rule_struct_rcu * rule;
  size_t allocsize = 0;
  int i = 0;

  if(ruleset_out_rcufree == NULL)
  {
    LOG_ERR(packet_id, "ruleset_out is null");
    return -1;
  }

  rcu_read_lock();
  list_for_each_entry_rcu(rule, &rules_list, list)
  {
    i++;
  }
  rcu_read_unlock();

  // NB: large allocations can't be freed by rcu when the tag offset is too large.
  // luckily, we need the tag at the front of the struct to have an internal variable length array.
  // see __is_kvfree_rcu_offset
  allocsize = sizeof(struct ruleset_struct_rcu) + sizeof(struct rule_struct) * i;

  *ruleset_out_rcufree = kzalloc(allocsize, GFP_ATOMIC );
  if(*ruleset_out_rcufree == NULL)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return -1;
  }

  (*ruleset_out_rcufree)->count = i;

  i = 0;
  rcu_read_lock();
  list_for_each_entry_rcu(rule, &rules_list, list)
  {
    memcpy( &((*ruleset_out_rcufree)->rules[i]), &(rule->r), sizeof(struct rule_struct) ); // todo: use i++
  }
  rcu_read_unlock();

  return 0;
}

void rules_append(const char * process_path, const bool is_allowed, const uint32_t packet_id)
{
  struct rule_struct_rcu * rule;

  if (process_path == NULL)
  {
    LOG_ERR(packet_id, "process_path is null");
    return;
  }

  if (strlen(process_path) > PATH_LENGTH)
  {
    LOG_ERR(packet_id, "process_path too long");
    return;
  }

  rule = (struct rule_struct_rcu *)kzalloc(sizeof(struct rule_struct_rcu), GFP_ATOMIC);
  if(rule == NULL)
  {
    LOG_ERR(packet_id, "kzmalloc failed");
    return;
  }

  strncpy(rule->r.process_path, process_path, PATH_LENGTH);
  rule->r.allowed = is_allowed;

  spin_lock(&rules_lock);
  rcu_read_lock();
  list_add_tail_rcu(&rule->list, &rules_list);
  rcu_read_unlock();
  spin_unlock(&rules_lock);

  LOG_DEBUG(packet_id, "%s %s", (rule->r.allowed ? "allowed" : "blocked"), rule->r.process_path);
}

void rules_clear(const uint32_t packet_id)
{
  struct rule_struct_rcu * rule;
  int rule_cleaned_records = 0;

  if (list_empty(&rules_list))
  {
    LOG_DEBUG(packet_id, "rules_list empty");
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

  LOG_DEBUG(packet_id, "%d rule(s) successfully cleaned", rule_cleaned_records);
}

void rules_remove(const unsigned char * process_path, const uint32_t packet_id)
{
  struct rule_struct_rcu * rule;

  if (process_path == NULL)
  {
    LOG_ERR(packet_id, "process_path is null");
    return;
  }

  if (strlen(process_path) > PATH_LENGTH)
  {
    LOG_ERR(packet_id, "process_path too long");
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

      LOG_DEBUG(packet_id, "deleted rule for %s", process_path);
      return;
    }
  }
  rcu_read_unlock();
  spin_unlock(&rules_lock);

  LOG_DEBUG(packet_id, "no rule to delete for %s", process_path);
}

int rules_search(struct rule_struct * rule_out, uint32_t protocol, const unsigned char * process_path, const uint32_t packet_id)
{
  // todo: handle wildcards for protocol and pathroot
  // for all rules, ensure any process_path entries that end with '/' set match_parentpath to true
  // calc hashes for both process_path arg and the parent_path
  // when searching each of accept_list or block_list:
  // - pa1 match occurs when process_paths match
  // - pr1 match occurs when protocols match
  // - pa* match occurs when match_parentpath true and parent_path hash matches process_path hash
  // - pr* match occurs when protocol is ~0
  // - m1 match = pa1 and pr1
  // - m2 match = pa1 and pr*
  // - m3 match = pa* and pr1
  // - accept when m1 or m2 or m3 in accept_list
  // - block when m1 or m2 or m3 in block_list
  // the personality_flag should control the comparison order, either search accept_list first or block_list first: tolerant or protective (default)

  struct rule_struct_rcu * rule;

  if (process_path == NULL)
  {
    LOG_ERR(packet_id, "process_path is null");
    return -1;
  }

  if (strlen(process_path) > PATH_LENGTH)
  {
    LOG_ERR(packet_id, "process_path too long");
    return -1;
  }

  rcu_read_lock();
  list_for_each_entry_rcu(rule, &rules_list, list)
  {
    if (strncmp(rule->r.process_path, process_path, PATH_LENGTH) == 0)
    {
      LOG_DEBUG(packet_id, "found %s %s", (rule->r.allowed ? "allowed" : "blocked"), rule->r.process_path);
      memcpy(rule_out, &rule->r, sizeof(struct rule_struct));

      rcu_read_unlock();
      return 0;
    }
  }
  rcu_read_unlock();

  LOG_DEBUG(packet_id, "rule not found for %s", process_path);
  return -1;
}
