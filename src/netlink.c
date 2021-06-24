// eftirlit7 (gpl2) - orthopteroid@gmail.com
// forked from douane-lkms (gpl2) - zedtux@zedroot.org

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

//#include <linux/module.h>
//#include <linux/kernel.h>
#include <net/genetlink.h>

// http://people.ee.ethz.ch/~arkeller/linux/multi/kernel_user_space_howto-3.html
// http://www.electronicsfaq.com/2014/02/generic-netlink-sockets-example-code.html
// debug with: genl-ctrl-list -d

#include "module.h"
#include "types.h"
#include "netfilter.h"
#include "rules.h"
#include "netlink.h"
#include "defs.h"

//////////////////

#define DEBUG_ENL_PROTOCOL
//#define DEBUG_ENL_ASYNC

// make all communic with userspace async via workq for packet storm protection
// review: ovbious latency issues with hi priority messages
#define ENL_ASYNC_SEND 1

#ifdef DEBUG_ENL_PROTOCOL
#define LOG_DEBUG_PROTO LOG_DEBUG
#else // DEBUG_ENL_PROTOCOL
#define LOG_DEBUG_PROTO(fmt, ...) do {} while(false)
#endif // DEBUG_ENL_PROTOCOL

#ifdef DEBUG_ENL_ASYNC
#define LOG_DEBUG_ASYNC LOG_DEBUG
#else // DEBUG_ENL_ASYNC
#define LOG_DEBUG_ASYNC(fmt, ...) do {} while(false)
#endif // DEBUG_ENL_ASYNC

DEFINE_SPINLOCK(nl_lock); // protects np_port and nl_net. todo: remove somehow....

static int nl_port = 0;
static struct net * nl_net = NULL;

static struct genl_family enl_family; // fwd decl

// rcu-friendly variable size array of netlink attrib pointers
struct nlattrptr_stack_rcu
{
  struct rcu_head rcu;
  //
  struct nlattr * a[];
};

struct async_message
{
  int port;
  struct net * net;
  struct sk_buff * msg;
  uint32_t stack_id;
  //
  struct work_struct worker;
  struct rcu_head rcu;
};

DEFINE_SPINLOCK(nlq_workq_lock);
struct workqueue_struct * nlq_workq;

/////////

static uint32_t enl__stackid(void)
{
  uint32_t id;
  get_random_bytes(&id, sizeof(id));
  return id;
}

static void enl__wq_send(struct work_struct *work)
{
  struct async_message * am = container_of(work, struct async_message, worker);
  int rc = 0;

  if(am->net == NULL || am->port == 0)
  {
    rc = ENXIO;
  }
  else
  {
    // m->msg is always handed off, even on error.
    // see impl of netlink_unicast
    rc = genlmsg_unicast(am->net, am->msg, am->port);
  }

  if(rc)
  {
    LOG_ERR(am->stack_id, "async enqueue error %d", rc);
  }
  else
  {
    LOG_DEBUG_ASYNC(am->stack_id, "async work complete");
  }

  kfree_rcu(am, rcu);
}

/////////

void enl__get_connect(struct net ** net, int * port)
{
  spin_lock(&nl_lock);
  *port = nl_port;
  *net = nl_net;
  spin_unlock(&nl_lock);
}

void enl__set_connect(struct net * net, int port)
{
  spin_lock(&nl_lock);
  nl_port = port;
  nl_net = net;
  spin_unlock(&nl_lock);
}

/////////

struct MSGSTATE
{
  struct sk_buff * msg;
  void * hdr;
  int err;
};

static void enl__prep_reclaim(struct MSGSTATE * ms)
{
  if (ms->msg) nlmsg_free(ms->msg);
  ms->msg = 0;
  ms->hdr = 0;
}

static bool enl__prep(struct MSGSTATE * ms, int comm)
{
  ms->msg = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
  if (!ms->msg)
  {
    ms->err = -ENOMEM;
    return false;
  }

  // oddly, genlmsg_put(...) is different in kernel space
  // seq num irrelevant as userspace is using nl_socket_disable_seq_check
  ms->hdr = genlmsg_put(ms->msg, 0, 0 /* seq num */, &enl_family, 0, comm);
  if (!ms->hdr)
  {
    enl__prep_reclaim(ms);
    ms->err = -ENOMEM; // but really a problem with the skb's tail pointer
    return false;
  }

  return true;
}

#ifdef ENL_ASYNC_SEND

static bool enl__send(struct MSGSTATE * ms, const uint32_t stack_id)
{
  int port;
  struct net * net;

  if (!ms->msg || !ms->hdr)
  {
    ms->err = -EINVAL;
    goto fail;
  }

  genlmsg_end(ms->msg, ms->hdr);

  enl__get_connect(&net, &port);

  if(nl_net == NULL || nl_port == 0)
  {
    ms->err = -ENXIO;
    goto fail;
  }

  {
    struct async_message * am = kzalloc(sizeof(struct async_message), GFP_ATOMIC);
    if (!am)
    {
      LOG_ERR(stack_id, "kzalloc failure");
      ms->err = -ENOMEM;
      goto fail;
    }
    if (!nlq_workq)
    {
      LOG_ERR(stack_id, "!nlq_workq");
      ms->err = -1;
      goto fail;
    }

    LOG_DEBUG_ASYNC(stack_id, "queueing async call");

    am->stack_id = stack_id;
    am->port = port;
    am->net = net;
    am->msg = ms->msg;
    //
    INIT_WORK(&am->worker, enl__wq_send);

    spin_lock_bh(&nlq_workq_lock);
    queue_work(nlq_workq, &am->worker);
    spin_unlock_bh(&nlq_workq_lock);
  }

  ms->err = 0;
  ms->msg = 0; // mark as handed off
  ms->hdr = 0;

fail:
  return ms->err == 0;
}

#else // ENL_ASYNC_SEND

static bool enl__send(struct MSGSTATE * ms, const uint32_t stack_id)
{
  int port;
  struct net * net;

  if (!ms->msg || !ms->hdr)
  {
    ms->err = -EINVAL;
    return false;
  }

  genlmsg_end(ms->msg, ms->hdr);

  enl__get_connect(&net, &port);

  if(net == NULL || port == 0)
  {
    ms->err = -ENXIO;
    goto fail;
  }

  // ms->msg is always handed off, even on error.
  // see impl of netlink_unicast
  ms->err = genlmsg_unicast(net, ms->msg, port);
  ms->msg = 0; // mark as handed off
  ms->hdr = 0;

fail:
  if(ms->err != 0)
    LOG_ERR(stack_id, "error %d", ms->err);

  return ms->err == 0;
}

#endif // ENL_ASYNC_SEND

int enl__send_error(const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0, 0 };

  LOG_DEBUG(stack_id, "sending error");

  if(!enl__prep(&ms, ENL_COMM_ERROR)) goto fail;
  if(!enl__send(&ms, stack_id)) goto fail;

  return ms.err;

fail:
  enl__prep_reclaim(&ms);

  LOG_ERR(stack_id, "error %d", ms.err);
  return ms.err;
}

int enl__send_query(const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0, 0 };
  struct nlattrptr_stack_rcu * stack = 0;
  struct ruleset_struct_rcu * ruleset = 0;
  int count, s, r;

  if(0>(ms.err=rules_get(&ruleset, stack_id))) goto out;

  count = ruleset->count +1; // +1 for fw-state
  stack = kzalloc(sizeof(struct nlattrptr_stack_rcu) + sizeof(struct nlattr *) * count, GFP_ATOMIC );
  if(stack == NULL) { ms.err=-1; goto out; }

  if(!enl__prep(&ms, ENL_COMM_QUERY)) goto out;

  // fw mode then other entries
  s = 0;
  if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_STATE, def_flag_value[E7F_MODE]))) goto out;
  if(0<ruleset->count) stack->a[s++] = nla_nest_start(ms.msg, ENL_ATTR_NESTED | NLA_F_NESTED); // | NESTED required with ubuntu libnl 3.2.29
  for(r=0; r<ruleset->count; s++, r++)
  {
    if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_STATE, (ruleset->rules[r].allowed) ? E7C_ALLOW : E7C_BLOCK))) goto out;
    if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_PROT, ruleset->rules[r].protocol))) goto out;
    if(0>(ms.err=nla_put_string(ms.msg, ENL_ATTR_PATH, ruleset->rules[r].process_path))) goto out;

    // nesting on all but last entry
    if(s+1<count) stack->a[s] = nla_nest_start(ms.msg, ENL_ATTR_NESTED | NLA_F_NESTED); // | NESTED required with ubuntu libnl 3.2.29
  }
  for(s=count -2; s>=0; s--) nla_nest_end(ms.msg, stack->a[ s ]); // start at -2 because last entry is not nested
  if(!enl__send(&ms, stack_id)) goto out;

out:
  if(ruleset) kfree_rcu(ruleset, rcu);
  if(stack) kfree_rcu(stack, rcu);
  if(ms.err)
  {
    enl__prep_reclaim(&ms);
    LOG_ERR(stack_id, "error %d", ms.err);
  }
  return ms.err;
}

/////////////////

int enl_send_disconnect(const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0, 0 };

  if(!enl__prep(&ms, ENL_COMM_DISCONNECT)) goto fail;
  if(!enl__send(&ms, stack_id)) goto fail;

  return ms.err;

fail:
  enl__prep_reclaim(&ms);

  LOG_ERR(stack_id, "error %d", ms.err);
  return ms.err;
}

int enl_send_event(uint32_t state, uint32_t prot, const char * path, const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0, 0 };

  if(!enl__prep(&ms, ENL_COMM_EVENT)) goto fail;
  if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_STATE, state))) goto fail;
  if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_PROT, prot))) goto fail;
  if(0>(ms.err=nla_put_string(ms.msg, ENL_ATTR_PATH, path))) goto fail;
  if(!enl__send(&ms, stack_id)) goto fail;

  return ms.err;

fail:
  enl__prep_reclaim(&ms);

  LOG_ERR(stack_id, "error %d", ms.err);
  return ms.err;
}

////////////////////

static int enl__comm_error(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();

  LOG_DEBUG_PROTO(stack_id, "unexpected");
  enl__send_error(stack_id);

  return 0;
}

static int enl__comm_disconnect(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();

  enl__set_connect(NULL, 0);
  LOG_DEBUG(stack_id, "daemon disconnected");

  return 0;
}

static int enl__comm_block(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  bool connected = enl_is_connected();
  struct nlattr *pa, *pr;
  bool ok = false;
  uint32_t u32;
  char * sz;

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
    { LOG_ERR(stack_id, "rejected from unprivileged process"); return 0; }

  // todo: check for connection theft
  enl__set_connect(genl_info_net(info), info->snd_portid);
  if(!connected)
    LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  if((pr = info->attrs[ENL_ATTR_PROT])) u32 = nla_get_u32(pr);
  if((pa = info->attrs[ENL_ATTR_PATH])) sz = (char*)nla_data(pa); // sz = nla_get_string(a);

  if(!pa && !pr)     def_flag_value[E7F_MODE] = E7C_BLOCK; // fw drop all
  else if(!pa && pr) ok = rules_add(u32, "", false, stack_id);
  else if(pa && !pr) ok = rules_add(E7C_IP_ANY, sz, false, stack_id);
  else if(pa && pr)  ok = rules_add(u32, sz, false, stack_id);

  if(!ok)
    enl__send_error(stack_id);
  else if(def_flag_value[E7F_RULE_CHANGE_QUERY] == E7C_ENABLED)
    enl__send_query(stack_id);

  return 0;
}

static int enl__comm_allow(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  bool connected = enl_is_connected();
  struct nlattr *pa, *pr;
  bool ok = false;
  uint32_t u32;
  char * sz;

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
    { LOG_ERR(stack_id, "rejected from unprivileged process"); return 0; }

  // todo: check for connection theft
  enl__set_connect(genl_info_net(info), info->snd_portid);
  if(!connected)
    LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  if((pr = info->attrs[ENL_ATTR_PROT])) u32 = nla_get_u32(pr);
  if((pa = info->attrs[ENL_ATTR_PATH])) sz = (char*)nla_data(pa); // sz = nla_get_string(a);

  if(!pa && !pr)     def_flag_value[E7F_MODE] = E7C_DISABLED; // fw off
  else if(!pa && pr) ok = rules_add(u32, "", true, stack_id);
  else if(pa && !pr) ok = rules_add(E7C_IP_ANY, sz, true, stack_id);
  else if(pa && pr)  ok = rules_add(u32, sz, true, stack_id);

  if(!ok)
    enl__send_error(stack_id);
  else if(def_flag_value[E7F_RULE_CHANGE_QUERY] == E7C_ENABLED)
    enl__send_query(stack_id);

  return 0;
}

static int enl__comm_enable(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  bool connected = enl_is_connected();

  // todo: check for connection theft
  enl__set_connect(genl_info_net(info), info->snd_portid);
  if(!connected)
    LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  def_flag_value[E7F_MODE] = E7C_ENABLED;
  return 0;
}

static int enl__comm_clear(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  bool connected = enl_is_connected();
  struct nlattr *pa = NULL, *pr = NULL, *st = NULL;
  uint32_t u32 = 0, state = 0;
  char * sz = NULL;

  // todo: check for connection theft
  enl__set_connect(genl_info_net(info), info->snd_portid);
  if(!connected)
    LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  if((st = info->attrs[ENL_ATTR_STATE])) state = nla_get_u32(st);
  if((pr = info->attrs[ENL_ATTR_PROT])) u32 = nla_get_u32(pr);
  if((pa = info->attrs[ENL_ATTR_PATH])) sz = (char*)nla_data(pa); // sz = nla_get_string(a);

  if(st)
  {
    switch(state) // with an arg, queries a particular list
    {
      case E7C_BLOCK: rules_clear_state(false, stack_id); break;
      case E7C_ALLOW: rules_clear_state(true, stack_id); break;
      default:        enl__send_error(stack_id);
    }
  }
  else if(!pa && !pr) rules_clear(stack_id); // no args clears all rules
  else if(!pa && pr)  rules_remove(u32, "", stack_id);
  else if(pa && !pr)  rules_remove(E7C_IP_ANY, sz, stack_id);
  else if(pa && pr)   rules_remove(u32, sz, stack_id);

  if(def_flag_value[E7F_RULE_CHANGE_QUERY] == E7C_ENABLED)
    enl__send_query(stack_id);

  return 0;
}

static int enl__comm_query(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  bool connected = enl_is_connected();

  // todo: check for connection theft
  enl__set_connect(genl_info_net(info), info->snd_portid);
  if(!connected) LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  enl__send_query(stack_id);
  return 0;
}

static int enl__comm_event(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  LOG_DEBUG_PROTO(stack_id, " unexpected");
  return 0;
}

static int enl__comm_set(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  bool connected = enl_is_connected();
  struct nlattr * a = NULL;
  uint32_t u32 = 0;
  const char * sz = 0;
  int flag = 0;

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
    { LOG_ERR(stack_id, "rejected from unprivileged process"); return 0; }

  // todo: check for connection theft
  enl__set_connect(genl_info_net(info), info->snd_portid);
  if(!connected)
    LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  if((a = info->attrs[ENL_ATTR_FLAG])) flag = nla_get_u32(a);
  if((a = info->attrs[ENL_ATTR_VALUE])) u32 = nla_get_u32(a);

  if(!(sz=def_flag_name_str(flag)))
    { LOG_ERR(stack_id, "bad flag id %d", flag); return 0; }

  def_flag_value[flag] = u32;

  return 0;
}

static int enl__comm_get(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  bool connected = enl_is_connected();
  struct MSGSTATE ms = { 0, 0, 0 };
  struct nlattr * a = NULL;
  const char * sz = 0;
  int flag = 0;

  // todo: check for connection theft
  enl__set_connect(genl_info_net(info), info->snd_portid);
  if(!connected)
    LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  if((a = info->attrs[ENL_ATTR_FLAG])) flag = nla_get_u32(a);

  if(!(sz=def_flag_name_str(flag)))
  {
    LOG_ERR(stack_id, "bad flag id %d", flag);
    return 0;
  }

  if(!enl__prep(&ms, ENL_COMM_GET)) goto fail;
  if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_FLAG, flag))) goto fail;
  if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_VALUE, def_flag_value[flag]))) goto fail;
  if(!enl__send(&ms, stack_id)) goto fail;

  return 0;

fail:
  enl__prep_reclaim(&ms);

  LOG_ERR(stack_id, "error %d", ms.err);
  return 0;
}

////////////////////

// command/handler mapping
struct genl_ops enl_ops[] = {
  { .cmd = ENL_COMM_ERROR, .doit = enl__comm_error, },
  { .cmd = ENL_COMM_DISCONNECT, .doit = enl__comm_disconnect, },
  { .cmd = ENL_COMM_BLOCK, .doit = enl__comm_block, .flags = GENL_ADMIN_PERM, },
  { .cmd = ENL_COMM_ALLOW, .doit = enl__comm_allow, .flags = GENL_ADMIN_PERM, },
  { .cmd = ENL_COMM_ENABLE, .doit = enl__comm_enable, .flags = GENL_ADMIN_PERM, },
  { .cmd = ENL_COMM_CLEAR, .doit = enl__comm_clear, .flags = GENL_ADMIN_PERM, },
  { .cmd = ENL_COMM_QUERY, .doit = enl__comm_query, },
  { .cmd = ENL_COMM_EVENT, .doit = enl__comm_event, },
  { .cmd = ENL_COMM_SET, .doit = enl__comm_set, .flags = GENL_ADMIN_PERM, },
  { .cmd = ENL_COMM_GET, .doit = enl__comm_get, },
};

//family definition
static struct genl_family enl_family /*__ro_after_init*/ = {
  .hdrsize = 0,
  .maxattr = ENL_ATTR_MAX,
  .policy = def_policy,
  .ops = enl_ops,
  .n_ops = ENL_COMM_MAX,
};

int enl_is_connected(void)
{
  bool connected = false;

  spin_lock(&nl_lock);
  connected = (0!=nl_port) && (0!=nl_net);
  spin_unlock(&nl_lock);

  return connected;
}

int enl_init()
{
  int rc;

  strncpy(enl_family.name, ENL_NAME, GENL_NAMSIZ);
  enl_family.version = ENL_VERSION;

  if ((rc = genl_register_family(&enl_family)) != 0)
  {
    LOG_ERR(0, "genl_register_family failed %d", rc);
    return -1;
  }

  // buffer all events back to userspace
  nlq_workq = alloc_ordered_workqueue("%s", WQ_HIGHPRI, "e7_nlq"); // review: WQ_HIGHPRI
  if (!nlq_workq)
  {
    LOG_ERR(0, "alloc_ordered_workqueue failed");
    return -1;
  }

  return 0;
}

void enl_exit(void)
{
  // review: workq clear first?
  destroy_workqueue(nlq_workq);
  nlq_workq = NULL;

  if (genl_unregister_family(&enl_family) != 0)
  {
    LOG_ERR(0, "genl_unregister_family failed");
  }
}
