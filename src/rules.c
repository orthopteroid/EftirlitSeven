// eftirlit7 (gpl2) - orthopteroid@gmail.com

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
#include <asm-generic/qrwlock.h>

#include "module.h"
#include "fnv1a32.h"
#include "rules.h"
#include "defs.h"

#define ALIGNED ____cacheline_aligned

#define CIRCQ_SLOTS 128

typedef char process_path_t[PATH_LENGTH +1];

// struct-of-array layout for better cpu performance
struct rule_data
{
  uint32_t       protocol[CIRCQ_SLOTS] ALIGNED;
  uint32_t       allowed[CIRCQ_SLOTS] ALIGNED;
  uint32_t       path_hash[CIRCQ_SLOTS] ALIGNED;
  uint32_t       path_len[CIRCQ_SLOTS] ALIGNED;
  process_path_t path[CIRCQ_SLOTS] ALIGNED; // stick at end of struct
};

struct rule_data * rule_data = 0;

static int rules_circq_front = 0;
static int rules_circq_size = 0;

struct qrwlock rules_rwlock = __ARCH_RW_LOCK_UNLOCKED;

//////////////////////

bool rules__check_path(const char * process_path, const uint32_t packet_id)
{
  if (process_path == NULL)
  {
    LOG_ERR(packet_id, "process_path is null");
    return false;
  }

  if (strlen(process_path) > PATH_LENGTH)
  {
    LOG_ERR(packet_id, "process_path too long");
    return false;
  }

  return true;
}

////

void rules_print(const uint32_t packet_id)
{
  int i, k;

  queued_read_lock(&rules_rwlock);

  for(i=0, k=rules_circq_front; i<rules_circq_size; i++, k++)
  {
    if (k == CIRCQ_SLOTS) k = 0;
    LOG_DEBUG(packet_id, "(%u:%s) %s", rule_data->protocol[k], rule_data->path[k], (rule_data->allowed[k] ? "allowed" : "blocked"));
  }

  queued_read_unlock(&rules_rwlock);
}

void rules_clear(const uint32_t packet_id)
{
  queued_write_lock(&rules_rwlock);

  rules_circq_front = 0;
  rules_circq_size = 0;

  queued_write_unlock(&rules_rwlock);
}

void rules_clear_state(const bool is_allowed, const uint32_t packet_id)
{
  int i, k;

  queued_write_lock(&rules_rwlock);

  for(i=0, k=rules_circq_front; i<rules_circq_size; i++, k++)
  {
    if (k == CIRCQ_SLOTS) k = 0;
    if (rule_data->allowed[k] != is_allowed) continue;

    rules_circq_size--;
    if(0==rules_circq_size) return;

    rule_data->allowed[k] = rule_data->allowed[rules_circq_front];
    rule_data->protocol[k] = rule_data->protocol[rules_circq_front];
    rule_data->path_hash[k] = rule_data->path_hash[rules_circq_front];
    rule_data->path_len[k] = rule_data->path_len[rules_circq_front];
    strncpy(rule_data->path[k], rule_data->path[rules_circq_front], PATH_LENGTH);

    rules_circq_front++;
    if (rules_circq_front == CIRCQ_SLOTS) rules_circq_front = 0;
  }

  queued_write_unlock(&rules_rwlock);
}

int rules_get(struct ruleset_struct_rcu ** ruleset_out_rcufree, const uint32_t packet_id)
{
  struct rule_struct * rule;
  size_t allocsize = 0;
  int i, k;
  int rc = 0;

  if(!ruleset_out_rcufree)
  {
    LOG_ERR(packet_id, "!ruleset_out_rcufree");
    return -1;
  }

  queued_read_lock(&rules_rwlock);

  // NB: large allocations can't be freed by rcu when the tag offset is too large.
  // luckily, we need the tag at the front of the struct to have an internal variable length array.
  // see __is_kvfree_rcu_offset
  allocsize = sizeof(struct ruleset_struct_rcu) + sizeof(struct rule_struct) * rules_circq_size;

  *ruleset_out_rcufree = kzalloc(allocsize, GFP_ATOMIC);
  if(!(*ruleset_out_rcufree))
  {
    LOG_ERR(packet_id, "kzalloc failure %lu %p", allocsize, *ruleset_out_rcufree);
    rc = -ENOMEM;
    goto out;
  }

  (*ruleset_out_rcufree)->count = rules_circq_size;

  for(i=0, k=rules_circq_front; i<rules_circq_size; i++, k++)
  {
    if (k == CIRCQ_SLOTS) k = 0;
    rule = &((*ruleset_out_rcufree)->rules[i]);
    rule->allowed = rule_data->allowed[k];
    rule->protocol = rule_data->protocol[k];
    strncpy(rule->process_path, rule_data->path[k], PATH_LENGTH);
  }

out:
  queued_read_unlock(&rules_rwlock);
  return rc;
}

bool rules_add(uint32_t protocol, const char * process_path, const bool is_allowed, const uint32_t packet_id)
{
  uint32_t path_len = 0;
  uint32_t path_hash = 0;
  const char *szprot0 = 0, *szprot1 = 0;
  bool dupl = false, full = false;
  int i, k;

  if(!rules__check_path(process_path, packet_id)) return false;

  path_len = strlen(process_path);
  path_hash = e7_fnv1a32(process_path);

  queued_write_lock(&rules_rwlock);

  if(rules_circq_size==CIRCQ_SLOTS)
    { full = true; goto out; }

  // exact match search
  for(i=0, k=rules_circq_front; i<rules_circq_size; i++, k++)
  {
    if (k == CIRCQ_SLOTS) k = 0;
    if (rule_data->protocol[k] != protocol) continue;
    if (rule_data->path_hash[k] != path_hash) continue;
    if (rule_data->path_len[k] != path_len) continue;
    if (strncmp(rule_data->path[k], process_path, PATH_LENGTH) != 0) continue;

    dupl = true;
    goto out;
  }

  k = rules_circq_front + rules_circq_size;
  if (k >= CIRCQ_SLOTS) k -= CIRCQ_SLOTS;
  rules_circq_size++;

  rule_data->allowed[k] = is_allowed;
  rule_data->protocol[k] = protocol;
  rule_data->path_hash[k] = path_hash;
  rule_data->path_len[k] = path_len;
  strncpy(rule_data->path[k], process_path, PATH_LENGTH);

out:
  queued_write_unlock(&rules_rwlock);

#ifdef DEBUG
  if(!def_protname(&szprot0, protocol)) szprot0 = "?";

  if(full)
    LOG_DEBUG(packet_id, "unable to add (%s:%s) - table full", szprot0, process_path);
  else if(dupl)
  {
    if(!def_protname(&szprot1, rule_data->protocol[k])) szprot1 = "?";
    LOG_DEBUG(packet_id, "searching for (%s:%s) - match (%s:%s) in slot %d, not adding", szprot0, process_path, szprot1, rule_data->path[k], k);
  }
  else
    LOG_DEBUG(packet_id, "searching for (%s:%s) - not found, added", szprot0, process_path);
#endif // DEBUG

  return !(full | dupl);
}

bool rules_remove(uint32_t protocol, const char * process_path, const uint32_t packet_id)
{
  uint32_t path_len = 0;
  uint32_t path_hash = 0;
  const char *szprot0 = 0, *szprot1 = 0;
  bool found = true;
  int i, k;

  if(!rules__check_path(process_path, packet_id)) return false;

  path_len = strlen(process_path);
  path_hash = e7_fnv1a32(process_path);

  queued_write_lock(&rules_rwlock);

  // exact match search
  for(i=0, k=rules_circq_front; i<rules_circq_size; i++, k++)
  {
    if (k == CIRCQ_SLOTS) k = 0;
    if (rule_data->protocol[k] != protocol) continue;
    if (rule_data->path_hash[k] != path_hash) continue;
    if (rule_data->path_len[k] != path_len) continue;
    if (strncmp(rule_data->path[k], process_path, PATH_LENGTH) != 0) continue;

    rules_circq_size--;
    if(0==rules_circq_size) return true;

    rule_data->allowed[k] = rule_data->allowed[rules_circq_front];
    rule_data->protocol[k] = rule_data->protocol[rules_circq_front];
    rule_data->path_hash[k] = rule_data->path_hash[rules_circq_front];
    rule_data->path_len[k] = rule_data->path_len[rules_circq_front];
    strncpy(rule_data->path[k], rule_data->path[rules_circq_front], PATH_LENGTH);

    rules_circq_front++;
    if (rules_circq_front == CIRCQ_SLOTS) rules_circq_front = 0;

    found = true;
    goto out;
  }

out:
  queued_write_unlock(&rules_rwlock);

#ifdef DEBUG
  if(!def_protname(&szprot0, protocol)) szprot0 = "?";

  if(found)
  {
    if(!def_protname(&szprot1, rule_data->protocol[k])) szprot1 = "?";
    LOG_DEBUG(packet_id, "searching for (%s:%s) - match (%s:%s) in slot %d", szprot0, process_path, szprot1, rule_data->path[k], k);
  }
  else
    LOG_DEBUG(packet_id, "searching for (%s:%s) - not found", szprot0, process_path);
#endif // DEBUG

  return found;
}

bool rules_search(struct rule_struct * rule_out, uint32_t protocol, const char * process_path, const uint32_t packet_id)
{
  uint32_t path_len = 0;
  uint32_t path_hash = 0;
  uint32_t parent_hash = 0;
  uint32_t parent_len = 0; // length incl last '/'
  const char *szprot0 = 0, *szprot1 = 0;
  int matchlevel = 0;
  int i, k;

  if(!rule_out)
    { LOG_ERR(packet_id, "!rule_out"); return false; }

  if(!rules__check_path(process_path, packet_id)) return false;

  path_len = strlen(process_path);
  path_hash = e7_fnv1a32(process_path);

  // todo: parse path to resolve escapes?
  for(i=0; process_path[i]; i++) { if(process_path[i]=='/') parent_len = i; }

  if(parent_len)
    parent_hash = e7_fnv1a32_len(process_path, parent_len);

  queued_read_lock(&rules_rwlock);

  // wildcard protocol of ~0 allowed
  for(i=0, k=rules_circq_front; i<rules_circq_size; i++, k++)
  {
    if (k == CIRCQ_SLOTS) k = 0;
    if ((rule_data->protocol[k] != E7C_IP_ANY) && (rule_data->protocol[k] != protocol)) continue;
    if (rule_data->path_hash[k] != path_hash) continue;
    if (rule_data->path_len[k] != path_len) continue;
    if (strncmp(rule_data->path[k], process_path, PATH_LENGTH) != 0) continue;

    matchlevel = 1;
    goto out;
  }

  // wildcard protocol of ~0 allowed
  // wildcard parent path allowed if ending in '/'
  if(parent_len)
  {
    for(i=0, k=rules_circq_front; i<rules_circq_size; i++, k++)
    {
      if (k == CIRCQ_SLOTS) k = 0;
      if ((rule_data->protocol[k] != E7C_IP_ANY) && (rule_data->protocol[k] != protocol)) continue;
      if (rule_data->path_hash[k] != parent_hash) continue;
      if (rule_data->path_len[k] != parent_len) continue;
      if (strncmp(rule_data->path[k], process_path, parent_len) != 0) continue;

      matchlevel = 2;
      goto out;
    }
  }

out:
  queued_read_unlock(&rules_rwlock);

#ifdef DEBUG
  if(!def_protname(&szprot0, protocol)) szprot0 = "?";

  if(matchlevel)
  {
    if(!def_protname(&szprot1, rule_data->protocol[k])) szprot1 = "?";
    LOG_DEBUG(packet_id, "searching for (%s:%s) - match code %d for (%s:%s) in slot %d", szprot0, process_path, matchlevel, szprot1, rule_data->path[k], k);
  }
  else
    LOG_DEBUG(packet_id, "searching for (%s:%s) - not found", szprot0, process_path);
#endif // DEBUG

  if(matchlevel)
  {
    rule_out->allowed = rule_data->allowed[k];
    rule_out->protocol = rule_data->protocol[k];
    strncpy(rule_out->process_path, rule_data->path[k], PATH_LENGTH);
  }

  return matchlevel > 0;
}

int rules_init(void)
{
  LOG_INFO(0, "queue %u entries %lu kb", CIRCQ_SLOTS, sizeof(struct rule_data) / 1024);
  rule_data = kzalloc(sizeof(struct rule_data), GFP_ATOMIC); // fixme
  if (!rule_data)
  {
    LOG_ERR(0, "kzalloc failed");
    return -1;
  }
  return 0;
}

void rules_exit(void)
{
  kfree(rule_data); // review: rcu?
}
