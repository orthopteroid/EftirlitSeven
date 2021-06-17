// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

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

#include <linux/module.h>
#include <linux/kernel.h>
#include <net/genetlink.h>

// http://people.ee.ethz.ch/~arkeller/linux/multi/kernel_user_space_howto-3.html
// http://www.electronicsfaq.com/2014/02/generic-netlink-sockets-example-code.html
// debug with: genl-ctrl-list -d

#include "module.h"
#include "types.h"
#include "douane.h"
#include "rules.h"
#include "netlink.h"
#include "flags.h"

////////////////////

#define E7X_NAME(x)       const char * ENL_NAME = #x;
#define E7X_VERSION(x)    const int ENL_VERSION = x;
#define E7X_CONST(x)
#define E7X_FLAG(x)
#define E7X_COMM(x)
#define E7X_ATTR(x, t)
  #include "e7_netlink.x"
#undef E7X_NAME
#undef E7X_VERSION
#undef E7X_CONST
#undef E7X_FLAG
#undef E7X_COMM
#undef E7X_ATTR

// const enumeration
enum {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)  x,
  #define E7X_FLAG(x)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)
  #include "e7_netlink.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

static const char * enl_state_name[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)  #x ,
  #define E7X_FLAG(x)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)
  #include "e7_netlink.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

// command enumeration (command 0 is not supported in netlink)
enum {
  ENL_COMM_UNSUPP,
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)
  #define E7X_COMM(x)     x,
  #define E7X_ATTR(x, t)
  #include "e7_netlink.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
  __ENL_COMM_MAX,
};
#define ENL_COMM_MAX (__ENL_COMM_MAX-1)

// attribute enumeration (attribute 0 is not supported in netlink)
enum {
  ENL_ATTR_UNSUPP,
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)  x,
  #include "e7_netlink.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
  __ENL_ATTR_MAX,
};
#define ENL_ATTR_MAX (__ENL_ATTR_MAX-1)

// attribute policies and types (attribute 0 is not supported in netlink)
static struct nla_policy enl_policy[] = {
  /*ENL_ATTR_UNSUPP*/ { },
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)  { .type = t },
  #include "e7_netlink.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

// command names (command 0 is not supported in netlink)
static const char * enl_comm_name[] = {
  "ENL_COMM_UNSUPP",
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)
  #define E7X_COMM(x)     #x ,
  #define E7X_ATTR(x, t)
  #include "e7_netlink.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

// attribute names (attribute 0 is not supported in netlink)
static const char * enl_attr_name[] = {
  "ENL_ATTR_UNSUPP" ,
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)  #x ,
  #include "e7_netlink.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

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
struct enl_recvfns * nl_rfns = NULL;

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

struct MSGSTATE
{
  struct sk_buff * msg;
  void * hdr;
  int err;
};

static void enl__checked_free(struct MSGSTATE * ms)
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
    enl__checked_free(ms);
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

  spin_lock(&nl_lock);
  port = nl_port;
  net = nl_net;
  spin_unlock(&nl_lock);

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

  spin_lock(&nl_lock);
  port = nl_port;
  net = nl_net;
  spin_unlock(&nl_lock);

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

/////////////////

int enl_send_disconnect(const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0, 0 };

  if(!enl__prep(&ms, ENL_COMM_DISCONNECT)) goto fail;
  if(!enl__send(&ms, stack_id)) goto fail;

  return ms.err;

fail:
  enl__checked_free(&ms);

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
  enl__checked_free(&ms);

  LOG_ERR(stack_id, "error %d", ms.err);
  return ms.err;
}
???
int enl_send_rules(int count, const struct rule_struct * rules, const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0, 0 };
  struct nlattrptr_stack_rcu * attrptr_stack = 0;
  int i, j;

  LOG_DEBUG(stack_id, "start");

  if(!enl__prep(&ms, ENL_COMM_RULES)) goto fail;

  attrptr_stack = kzalloc(sizeof(struct nlattrptr_stack_rcu) + sizeof(struct nlattr *) * count, GFP_ATOMIC );
  if(attrptr_stack == NULL) { ms.err=-1; goto fail; }

/*
  // a list built with recursive enumeration...
  std::deque<struct nlattr *> attrptr_stack;
  std::string inner;
  for(int z=0;z<3;z++)
  {
    // there appears to be overhead for each entry, but it seems to be around ENL_ATTR_MAX bytes. hmmm.
    inner = inner + "INNER ";
    attrptr_stack.push_front( nla_nest_start(ms.msg, ENL_ATTR_ECHONESTED | NLA_F_NESTED) ); // | NESTED required with ubuntu libnl 3.2.29
    enl_printrc( "nla_put_string", nla_put_string(ms.msg, ENL_ATTR_ECHOBODY, inner.c_str()) );
  }
  while(!attrptr_stack.empty())
  {
    nla_nest_end(ms.msg, attrptr_stack.front());
    attrptr_stack.pop_front();
  }
  enl_printrc( "enl_send", enl_send(&ms) );
*/

  // a list built with recursive enumeration...
  for(i = 0; i < count; i++)
  {
    attrptr_stack->a[i] = nla_nest_start(ms.msg, ENL_ATTR_RULENESTED | NLA_F_NESTED); // | NESTED required with ubuntu libnl 3.2.29

    if(0>(ms.err=nla_put_string(ms.msg, ENL_ATTR_PROCESS_STR, (const char*) &rules[i].process_path))) goto fail;
    if(0>(ms.err=nla_put_flag(ms.msg, rules[i].allowed ? ENL_ATTR_ALLOW : ENL_ATTR_BLOCK))) goto fail;
    //if(0>nla_put_flag(ms.msg, rules[i].enabled ? ENL_ATTR_ENABLE : ENL_ATTR_DISABLE)) goto fail;
    //if(0>nla_put_flag(ms.msg, rules[i].log ? ENL_ATTR_LOG : ENL_ATTR_NOLOG)) goto fail;
    //uint32_t cxtid;
    //bool manual;
  }
  for(j = 0; j < count; j++)
  {
    i = count - j;
    nla_nest_end(ms.msg, attrptr_stack->a[i]);
  }

  if(!enl__send(&ms, stack_id)) goto fail;

  LOG_DEBUG(stack_id, "complete");
  return ms.err;

fail:
  if(attrptr_stack) kfree_rcu(attrptr_stack, rcu);
  enl__checked_free(&ms);

  LOG_ERR(stack_id, "error %d", ms.err);
  return ms.err;
}

////////////////////

static int enl__comm_disconnect(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_DISCONNECT]);

  enl__connect(NULL, 0);
  LOG_DEBUG(stack_id, "daemon disconnected");

  return 0;
}

static int enl__comm_block(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  const char * szerror = NULL;
  bool connected = enl_is_connected();

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_BLOCK]);

  if(!netlink_capable(skb_in, CAP_NET_ADMIN)) { LOG_ERR(stack_id, "rejected from unprivileged process"); return 0; }

  // todo: check for connection theft
  enl__connect(genl_info_net(info), info->snd_portid);
  if(!connected) LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  do {
 } while(false);

  if(szerror) LOG_ERR(stack_id, szerror);
  return 0;
}

static int enl__comm_allow(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  const char * szerror = NULL;

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_ALLOW]);

  if(!netlink_capable(skb_in, CAP_NET_ADMIN)) { LOG_ERR(stack_id, "rejected from unprivileged process"); return 0; }

  // todo: check for connection theft
  enl__connect(genl_info_net(info), info->snd_portid);
  if(!connected) LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  do {
  } while(false);

  if(szerror) LOG_ERR(stack_id, szerror);
  return 0;
}

static int enl__comm_query(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  struct MSGSTATE ms = { 0, 0, 0 };
  struct nlattrptr_stack_rcu * stack = 0;
  int count, i, j;
  uint32_t state = 0;
  const char * test[] = { "one", "two", "three" };
  const char * testB[] = { "oneB", "twoB", "threeB" };
  const char * testA[] = { "oneA", "twoA", "threeA" };
  const char * testP[] = { "oneP", "twoP", "threeP" };

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_QUERY]);

  // todo: check for connection theft
  enl__connect(genl_info_net(info), info->snd_portid);
  if(!connected) LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  if(!attribs[ENL_ATTR_STATE])
  {
    // no args queries main fw state
    switch(flags_value[E7F_MODE])
    {
      case NF_ACCEPT: state = ENL_CONST_DISABLED; break;
      case NF_BLOCK: state = ENL_CONST_LOCKDOWN; break;
      case NF_IGNORE: state = ENL_CONST_ENABLED; break;
      default: state = ENL_CONST_ERROR;
    }
    if(!enl__prep(&ms, ENL_COMM_QUERY)) goto fail;
    if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_STATE, state))) goto fail;
    if(!enl__send(&ms, stack_id)) goto fail;
  }
  else
  {
    // with an arg, queries a particular list
    if(a = attribs[ENL_ATTR_STATE]) state = nla_get_u32(a);

    test = 0;
    switch(state)
    {
      case ENL_CONST_BLOCK:    test = testB; break;
      case ENL_CONST_ALLOW:    test = testA; break;
      case ENL_CONST_PENDING:  test = testP; break;
      default:
        if(!enl__prep(&ms, ENL_COMM_QUERY)) goto fail;
        if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_STATE, ENL_CONST_ERROR))) goto fail;
        if(!enl__send(&ms, stack_id)) goto fail;
    }

    if(test)
    {
      stack = kzalloc(sizeof(struct nlattrptr_stack_rcu) + sizeof(struct nlattr *) * count, GFP_ATOMIC );
      if(stack == NULL) { ms.err=-1; goto fail; }

      if(!enl__prep(&ms, ENL_COMM_QUERY)) goto fail;
      for(i=0; i<count; i++)
      {
        stack->a[i] = nla_nest_start(ms.msg, ENL_ATTR_NESTED | NLA_F_NESTED); // | NESTED required with ubuntu libnl 3.2.29
        if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_STATE, state))) goto fail;
        if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_PROT, 999))) goto fail;
        if(0>(ms.err=nla_put_string(ms.msg, ENL_ATTR_PATH, (const char*) &test[i]))) goto fail;
      }
      for(i=0; i<count; i++) nla_nest_end(ms.msg, stack->a[ count -i -1 ]);
      if(!enl__send(&ms, stack_id)) goto fail;
    }
  }

  if(stack) kfree_rcu(stack, rcu);
  LOG_DEBUG(stack_id, "complete");
  return 0;

fail:
  if(stack) kfree_rcu(stack, rcu);
  enl__checked_free(&ms);
  LOG_ERR(stack_id, "error %d", ms.err);
  return 0;
}

static int enl__comm_event(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  LOG_DEBUG_PROTO(stack_id, " unexpected %s", enl_comm_name[ENL_COMM_EVENT]);
  return 0;
}

static int enl__comm_set(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  struct nlattr * a = NULL;
  uint32_t u32 = 0;
  char * sz = 0;

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_SET]);

  if(!netlink_capable(skb_in, CAP_NET_ADMIN)) { LOG_ERR(stack_id, "rejected from unprivileged process"); return 0; }

  // todo: check for connection theft
  enl__connect(genl_info_net(info), info->snd_portid);
  if(!connected) LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  if(a = info->attrs[ENL_ATTR_FLAG]) sz = nla_get_string(a);
  if(a = attribs[ENL_ATTR_VALUE]) u32 = nla_get_u32(a);

  LOG_DEBUG(stack_id, "set %s %u", sz ? sz : "(null)", u32);

  if(-1==(flag=flag_lookup(sz))
  {
    LOG_ERR(stack_id, "bad flag name %s", sz);
    return 0;
  }

  flag_value[flag] = u32;

  return 0;
}

static int enl__comm_get(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  struct MSGSTATE ms = { 0, 0, 0 };
  struct nlattr * a = NULL;
  uint32_t u32 = 0;
  char * sz = 0;
  int flag = 0;

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_GET]);

  // todo: check for connection theft
  enl__connect(genl_info_net(info), info->snd_portid);
  if(!connected) LOG_DEBUG(stack_id, "connected to daemon NET %p PORT %u", nl_net, nl_port); // todo: pid and process name

  if(a = info->attrs[ENL_ATTR_STR]) sz = nla_get_string(a);

  LOG_DEBUG(stack_id, "get %s", sz ? sz : "(null)");

  if(-1==(flag=flag_lookup(sz))
  {
    LOG_ERR(stack_id, "bad flag name %s", sz);
    return 0;
  }

  if(!enl__prep(&ms, ENL_COMM_GET)) goto fail;
  if(0>(ms.err=nla_put_string(ms.msg, ENL_ATTR_FLAG, sz))) goto fail;
  if(0>(ms.err=nla_put_u32(ms.msg, ENL_ATTR_VALUE, flag_value[flag]))) goto fail;
  if(!enl__send(&ms, stack_id)) goto fail;

  return 0;

fail:
  enl__checked_free(&ms);

  LOG_ERR(stack_id, "error %d", ms.err);
  return 0;
}

////////////////////
/*
// An echo command, receives a message, prints it and sends another message back
static int enl__comm_echo(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  struct nlattr * tmp_attr;

  if(!nl_rfns) { LOG_ERR(stack_id, "!nl_rfns"); return -1; }

  tmp_attr = info->attrs[ENL_ATTR_ECHOBODY];
  if(tmp_attr)
  {
    char * message = (char*)nla_data(tmp_attr);
    if(!message) { LOG_ERR(stack_id, "!nla_data"); return -1; }

    LOG_DEBUG(stack_id, "received: %s", message);

    nl_rfns->recv_echo(message, stack_id);
  }

  if(info->attrs[ENL_ATTR_ECHONESTED])
  {
    struct nlattr * curr_attrs[ENL_ATTR_MAX +1]; // +1 because attrib 0 is nl_skipped

    memcpy(curr_attrs, info->attrs, sizeof(curr_attrs));

    // traverse the recursive enumeration, making the callback each time
    do {
      char * echostring = 0;
      int rc = 0;

      tmp_attr = curr_attrs[ENL_ATTR_ECHONESTED];
      if(!tmp_attr) break; // end-of-list

      memset(curr_attrs, 0, sizeof(curr_attrs));
      rc = nla_parse_nested(curr_attrs, ENL_ATTR_MAX, tmp_attr, enl_policy, NULL);
      if(rc!=0) { LOG_ERR(stack_id, "!nla_parse_nested"); return -1; }

      tmp_attr = curr_attrs[ENL_ATTR_ECHOBODY];
      if(!tmp_attr) { LOG_ERR(stack_id, "!ENL_ATTR_ECHOBODY"); return -1; }

      echostring = (char*)nla_data(tmp_attr);
      if(!echostring) { LOG_ERR(stack_id, "!nla_data"); return -1; }

      nl_rfns->recv_echo(echostring, stack_id);
    } while(true);
  }

  return 0;
}

static int enl__comm_event(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();
  LOG_DEBUG(stack_id, "called");
  return 0;
}

static int enl__comm_log(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_LOG]);

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
  {
    LOG_ERR(stack_id, "rejected from unprivileged process");
    return 0;
  }

  if (info->attrs[ENL_ATTR_ENABLE] && nl_rfns)
  {
    LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_ENABLE]);

    nl_rfns->flag_set(E7F_DEBUG, 1, stack_id);
  }
  if (info->attrs[ENL_ATTR_DISABLE] && nl_rfns)
  {
    LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_DISABLE]);

    nl_rfns->flag_set(E7F_DEBUG, 0, stack_id);
  }

  if (info->attrs[ENL_ATTR_QUERY])
  {
    struct MSGSTATE ms = { 0, 0, 0 };
    int logging = 0;

    LOG_DEBUG_PROTO(stack_id, "%s start", enl_attr_name[ENL_ATTR_QUERY]);

    nl_rfns->flag_get(E7F_DEBUG, &logging, stack_id);

    do {
      if(!enl__prep(&ms, ENL_COMM_LOG)) goto failquery;
      if(0>(ms.err=nla_put_flag(ms.msg, logging ? ENL_ATTR_ENABLE : ENL_ATTR_DISABLE))) goto failquery;
      if(!enl__send(&ms, stack_id)) goto failquery;

      LOG_DEBUG_PROTO(stack_id, "%s complete", enl_attr_name[ENL_ATTR_QUERY]);
      break;

failquery:
      enl__checked_free(&ms);
      LOG_ERR(stack_id, "%s error %d", enl_attr_name[ENL_ATTR_QUERY], ms.err);
    } while(false);
  }

  return 0;
}

static int enl__comm_mode(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_MODE]);

  if (info->attrs[ENL_ATTR_HELLO])
  {
    LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_HELLO]);

    spin_lock(&nl_lock);
    nl_port = info->snd_portid;
    nl_net = genl_info_net(info);
    spin_unlock(&nl_lock);
    LOG_DEBUG(stack_id, "daemon connection accepted NET %p PORT %u", nl_net, nl_port); // todo: pid and process name
  }
  if (info->attrs[ENL_ATTR_ENABLE] && nl_rfns)
  {
    LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_ENABLE]);

    nl_rfns->flag_set(E7F_MODE, -1, stack_id); // -1 == IGNORED
  }
  if (info->attrs[ENL_ATTR_DISABLE] && nl_rfns)
  {
    LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_DISABLE]);

    nl_rfns->flag_set(E7F_MODE, NF_ACCEPT, stack_id); // NF_ACCEPT == DISABLE
  }
  if (info->attrs[ENL_ATTR_QUERY] && nl_rfns)
  {
    struct MSGSTATE ms = { 0, 0, 0 };
    int early_action = 0;

    LOG_DEBUG_PROTO(stack_id, "%s start", enl_attr_name[ENL_ATTR_QUERY]);

    nl_rfns->flag_get(E7F_MODE, &early_action, stack_id);

    do {
      if(!enl__prep(&ms, ENL_COMM_MODE)) goto failquery;
      if(0>(ms.err=nla_put_flag(ms.msg, (early_action == NF_ACCEPT) ? ENL_ATTR_DISABLE : ENL_ATTR_ENABLE))) goto failquery;
      if(!enl__send(&ms, stack_id)) goto failquery;

      LOG_DEBUG_PROTO(stack_id, "%s complete", enl_attr_name[ENL_ATTR_QUERY]);
      break;

failquery:
      enl__checked_free(&ms);
      LOG_ERR(stack_id, "%s error %d", enl_attr_name[ENL_ATTR_QUERY], ms.err);
    } while(false);
  }
  if (info->attrs[ENL_ATTR_BYE])
  {
    LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_BYE]);

    spin_lock(&nl_lock);
    nl_port = 0;
    nl_net = 0;
    spin_unlock(&nl_lock);
    LOG_DEBUG(stack_id, "daemon disconnected");
  }

  return 0;
}

static int enl__comm_rule(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_RULE]);

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
  {
    LOG_ERR(stack_id, "rejected from unprivileged process");
    return 0;
  }

  // model after enl__comm_echo ?
  //LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_BYE]);

  {
    uint32_t u32proc = 0, u32prot = 0, u32user = 0, u32group = 0;
    char *szdev = "";
    struct nlattr *na = 0;
    struct rule_struct rule;

    memset(&rule, 0, sizeof(struct rule_struct));

    if ((na=info->attrs[ENL_ATTR_PROCESS_ID])) u32proc=nla_get_u32(na);
    if ((na=info->attrs[ENL_ATTR_PROTOCOL_ID])) u32prot=nla_get_u32(na);
    if ((na=info->attrs[ENL_ATTR_USER_ID])) u32user=nla_get_u32(na);
    if ((na=info->attrs[ENL_ATTR_GROUP_ID])) u32group=nla_get_u32(na);
    if ((na=info->attrs[ENL_ATTR_PROCESS_STR])) strncpy(rule.process_path, nla_data(na), PATH_LENGTH);
    if ((na=info->attrs[ENL_ATTR_DEVICE_STR])) szdev=nla_data(na); // not a copy

    rule.allowed = info->attrs[ENL_ATTR_ALLOW] ? true : false;
    rule.allowed = info->attrs[ENL_ATTR_BLOCK] ? false : true;
    //rule.enabled = info->attrs[ENL_ATTR_ENABLE] ? true : false;
    //rule.enabled = info->attrs[ENL_ATTR_DISABLE] ? false : true;
    //rule.log = info->attrs[ENL_ATTR_LOG] ? true : false;
    //rule.log = info->attrs[ENL_ATTR_NOLOG] ? false : true;


      if (info->attrs[ENL_ATTR_REMOVE])
      {
      }

    if(nl_rfns) nl_rfns->rule_add(&rule, stack_id);
  }

  return 0;
}

static int enl__comm_rules(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = enl__stackid();

  LOG_DEBUG_PROTO(stack_id, "%s", enl_comm_name[ENL_COMM_RULES]);

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
  {
    LOG_ERR(stack_id, "rejected from unprivileged process");
    return 0;
  }

  if (info->attrs[ENL_ATTR_CLEAR] && nl_rfns)
  {
    LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_CLEAR]);

    nl_rfns->rules_clear(stack_id);
  }

  if (info->attrs[ENL_ATTR_QUERY] && nl_rfns)
  {
    LOG_DEBUG_PROTO(stack_id, "%s", enl_attr_name[ENL_ATTR_QUERY]);

    nl_rfns->rules_query(stack_id);
  }

  return 0;
}
*/
///////

// command/handler mapping
struct genl_ops enl_ops[] = {
  { .cmd = ENL_COMM_DISCONNECT, .doit = enl__comm_disconnect, },
  { .cmd = ENL_COMM_BLOCK, .doit = enl__comm_block, .flags = GENL_ADMIN_PERM, },
  { .cmd = ENL_COMM_ALLOW, .doit = enl__comm_allow, .flags = GENL_ADMIN_PERM, },
  { .cmd = ENL_COMM_QUERY, .doit = enl__comm_query, },
  { .cmd = ENL_COMM_EVENT, .doit = enl__comm_event, }, // review: needed? wrong way anyway
  { .cmd = ENL_COMM_SET, .doit = enl__comm_set, .flags = GENL_ADMIN_PERM, },
  { .cmd = ENL_COMM_GET, .doit = enl__comm_get, },
};

//family definition
static struct genl_family enl_family /*__ro_after_init*/ = {
  .hdrsize = 0,
  .maxattr = ENL_ATTR_MAX,
  .policy = enl_policy,
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

void enl__connect(struct net * net, int port)
{
  spin_lock(&nl_lock);
  nl_port = port;
  nl_net = net;
  spin_unlock(&nl_lock);
}

int enl_init(struct enl_recvfns * rfns)
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

  nl_rfns = rfns;

  return 0;
}

void enl_exit(void)
{
  // review: workq clear first?
  destroy_workqueue(nlq_workq);
  nlq_workq = NULL;

  nl_rfns = NULL;

  if (genl_unregister_family(&enl_family) != 0)
  {
    LOG_ERR(0, "genl_unregister_family failed");
  }
}
