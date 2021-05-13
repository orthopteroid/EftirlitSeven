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
#include "douane_types.h"
#include "netlink.h"

////////////////////

#define DOUANE_NL_NAME "douane"
#define DOUANE_NL_VERSION 1

// <state> = enable | disable
// <criteria> = [process] [protocol] [device] [user] [group]
// <action> = (allow | block) [log | nolog]
// LOG u->m = <state> | query
// LOG u<-m = <state>
// MODE u->m = <state> | query | hello | bye
// MODE u<-m = <state> | bye
// RULE u->m = <criteria> <action> [<state> | remove]
// RULES u->m = query | clear
// RULES u<-m = <criteria> <action> <state>
// EVENT u<-m = <criteria>

// command enumeration
enum {
  DOUANE_NL_COMM_UNSUPP,
  DOUANE_NL_COMM_ECHO, // removeme: old demo code
  DOUANE_NL_COMM_LOG,
  DOUANE_NL_COMM_MODE,
  DOUANE_NL_COMM_RULE,
  DOUANE_NL_COMM_RULES,
  DOUANE_NL_COMM_EVENT,
  __DOUANE_NL_COMM_MAX,
};
#define DOUANE_NL_COMM_MAX (__DOUANE_NL_COMM_MAX-1)

// attribute enumeration
enum {
  DOUANE_NL_ATTR_UNSUPP,
  DOUANE_NL_ATTR_ECHOBODY, // removeme: old demo code
  DOUANE_NL_ATTR_ECHONESTED, // removeme: old demo code
  DOUANE_NL_ATTR_RULENESTED,
  // <state>
  DOUANE_NL_ATTR_ENABLE,
  DOUANE_NL_ATTR_DISABLE,
  // <criteria>
  DOUANE_NL_ATTR_PROCESS_ID,
  DOUANE_NL_ATTR_PROTOCOL_ID,
  DOUANE_NL_ATTR_USER_ID,
  DOUANE_NL_ATTR_GROUP_ID,
  DOUANE_NL_ATTR_PROCESS_STR,
  DOUANE_NL_ATTR_DEVICE_STR,
  // <action>
  DOUANE_NL_ATTR_ALLOW,
  DOUANE_NL_ATTR_BLOCK,
  DOUANE_NL_ATTR_LOG,
  DOUANE_NL_ATTR_NOLOG,
  // misc
  DOUANE_NL_ATTR_REMOVE,
  DOUANE_NL_ATTR_QUERY,
  DOUANE_NL_ATTR_CLEAR,
  DOUANE_NL_ATTR_HELLO,
  DOUANE_NL_ATTR_BYE,
  //
  __DOUANE_NL_ATTR_MAX,
};
#define DOUANE_NL_ATTR_MAX (__DOUANE_NL_ATTR_MAX-1)

// attribute policies and types
static struct nla_policy dnl_policy[] = {
  /*DOUANE_NL_ATTR_UNSUPP*/ {},
  /*DOUANE_NL_ATTR_ECHOBODY*/ { .type = NLA_NUL_STRING }, // removeme: old demo code
  /*DOUANE_NL_ATTR_ECHONESTED*/ { .type = NLA_NESTED }, // removeme: old demo code
  /*DOUANE_NL_ATTR_RULENESTED*/ { .type = NLA_NESTED },
  //
  /*ENABLE*/ { .type = NLA_FLAG },
  /*DISABLE*/ { .type = NLA_FLAG },
  //
  /*PROCESS_ID*/ { .type = NLA_U32 },
  /*PROTOCOL_ID*/ { .type = NLA_U32 },
  /*USER_ID*/ { .type = NLA_U32 },
  /*GROUP_ID*/ { .type = NLA_U32 },
  /*PROCESS_STR*/ { .type = NLA_NUL_STRING }, // .len sets max size?
  /*DEVICE_STR*/ { .type = NLA_NUL_STRING }, // .len sets max size?
  //
  /*ALLOW*/ { .type = NLA_FLAG },
  /*BLOCK*/ { .type = NLA_FLAG },
  /*LOG*/ { .type = NLA_FLAG },
  //
  /*REMOVE*/ { .type = NLA_FLAG },
  /*QUERY*/ { .type = NLA_FLAG },
  /*CLEAR*/ { .type = NLA_FLAG },
  /*HELLO*/ { .type = NLA_FLAG },
  /*BYE*/ { .type = NLA_FLAG },
};

static int nl_port = 0;
static struct net * nl_net = NULL;
struct dnl_recvfns * nl_rfns = NULL;

static struct genl_family dnl_family; // fwd decl

// rcu-friendly variable size array of netlink attrib pointers
struct nlattrptr_stack_rcu
{
  struct rcu_head rcu;
  //
  struct nlattr * a[];
};

/////////

static uint32_t _dnl_stackid(void)
{
  uint32_t id;
  get_random_bytes(&id, sizeof(id));
  return id;
}

/////////

struct MSGSTATE
{
  struct sk_buff * msg;
  void * hdr;
};

static int _dnl_prep(struct MSGSTATE * ms, int comm)
{
  ms->msg = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL); // todo: GFP_ATOMIC ?
  if (!ms->msg) return -1;

  // oddly, genlmsg_put(...) is different in kernel space
  // seq num irrelevant as userspace is using nl_socket_disable_seq_check
  ms->hdr = genlmsg_put(ms->msg, 0, 0 /* seq num */, &dnl_family, 0, comm);
  if (ms->hdr) return 0;

  if (ms->msg) nlmsg_free(ms->msg);
  ms->msg = 0;
  return -1;
}

static int _dnl_send(struct MSGSTATE * ms)
{
  if (!ms->msg || !ms->hdr) return -1;

  genlmsg_end(ms->msg, ms->hdr);

  if (0 != genlmsg_unicast(nl_net, ms->msg, nl_port))
  {
    nlmsg_free(ms->msg);
    ms->msg = 0;
    ms->hdr = 0;
    return -1;
  }

  ms->msg = 0;
  ms->hdr = 0;
  return 0;
}

static int _dnl_clean(struct MSGSTATE * ms)
{
  // clean after an error
  if (ms->msg /* && ms->hdr */) genlmsg_cancel(ms->msg, ms->hdr);
  if (ms->msg) nlmsg_free(ms->msg);

  ms->msg = 0;
  ms->hdr = 0;

  return -1;
}

/////////////////

int dnl_send_bye(const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0 };

  LOG_DEBUG(stack_id, "start");

  if (nl_net == NULL || nl_port == 0) goto prefail;
  if(0>_dnl_prep(&ms, DOUANE_NL_COMM_MODE)) goto fail;
  if(0>nla_put_flag(ms.msg, DOUANE_NL_ATTR_BYE)) goto fail;
  if(0>_dnl_send(&ms)) goto fail;

  LOG_DEBUG(stack_id, "complete");
  return 0;

prefail:
  LOG_ERR(stack_id, "prefail");
  return -1;

fail:
  LOG_ERR(stack_id, "error");
  return _dnl_clean(&ms);
}

int dnl_send_event(const char * process, const char * device, const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0 };

  LOG_DEBUG(stack_id, "start");

  if (nl_net == NULL || nl_port == 0) goto prefail;
  if(0>_dnl_prep(&ms, DOUANE_NL_COMM_EVENT)) goto fail;
  if(0>nla_put_string(ms.msg, DOUANE_NL_ATTR_PROCESS_STR, process)) goto fail;
  if(0>nla_put_string(ms.msg, DOUANE_NL_ATTR_DEVICE_STR, device)) goto fail;
  if(0>_dnl_send(&ms)) goto fail;

  LOG_DEBUG(stack_id, "complete");
  return 0;

prefail:
  LOG_ERR(stack_id, "prefail");
  return -1;

fail:
  LOG_ERR(stack_id, "error");
  return _dnl_clean(&ms);
}

int dnl_send_echo(const char * message, const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0 };

  LOG_DEBUG(stack_id, "start");

  if (nl_net == NULL || nl_port == 0) goto prefail;
  if(0>_dnl_prep(&ms, DOUANE_NL_COMM_EVENT)) goto fail;
  if(0>nla_put_string(ms.msg, DOUANE_NL_ATTR_ECHOBODY, message)) goto fail;
  if(0>_dnl_send(&ms)) goto fail;

  LOG_DEBUG(stack_id, "complete");
  return 0;

prefail:
  LOG_ERR(stack_id, "prefail");
  return -1;

fail:
  LOG_ERR(stack_id, "error");
  return _dnl_clean(&ms);
}

int dnl_send_rules(int count, const struct douane_rule * rules, const uint32_t stack_id)
{
  struct MSGSTATE ms = { 0, 0 };
  struct nlattrptr_stack_rcu * attrptr_stack = 0;
  int i, j;

  LOG_DEBUG(stack_id, "start");

  if (nl_net == NULL || nl_port == 0) goto prefail;
  if(0>_dnl_prep(&ms, DOUANE_NL_COMM_RULES)) goto fail;

  attrptr_stack = kzalloc(sizeof(struct nlattrptr_stack_rcu) + sizeof(struct nlattr *) * count, GFP_ATOMIC );
  if(attrptr_stack == NULL) goto fail;

/*
  // a list built with recursive enumeration...
  std::deque<struct nlattr *> attrptr_stack;
  std::string inner;
  for(int z=0;z<3;z++)
  {
    // there appears to be overhead for each entry, but it seems to be around DOUANE_NL_ATTR_MAX bytes. hmmm.
    inner = inner + "INNER ";
    attrptr_stack.push_front( nla_nest_start(ms.msg, DOUANE_NL_ATTR_ECHONESTED | NLA_F_NESTED) ); // | NESTED required with ubuntu libnl 3.2.29
    dnl_printrc( "nla_put_string", nla_put_string(ms.msg, DOUANE_NL_ATTR_ECHOBODY, inner.c_str()) );
  }
  while(!attrptr_stack.empty())
  {
    nla_nest_end(ms.msg, attrptr_stack.front());
    attrptr_stack.pop_front();
  }
  dnl_printrc( "dnl_send", dnl_send(&ms) );
*/

  // a list built with recursive enumeration...
  for(i = 0; i < count; i++)
  {
    attrptr_stack->a[i] = nla_nest_start(ms.msg, DOUANE_NL_ATTR_RULENESTED | NLA_F_NESTED); // | NESTED required with ubuntu libnl 3.2.29

    if(0>nla_put_string(ms.msg, DOUANE_NL_ATTR_PROCESS_STR, (const char*) &rules[i].process_path)) goto fail;
    if(0>nla_put_flag(ms.msg, rules[i].allowed ? DOUANE_NL_ATTR_ALLOW : DOUANE_NL_ATTR_BLOCK)) goto fail;
    //if(0>nla_put_flag(ms.msg, rules[i].enabled ? DOUANE_NL_ATTR_ENABLE : DOUANE_NL_ATTR_DISABLE)) goto fail;
    //if(0>nla_put_flag(ms.msg, rules[i].log ? DOUANE_NL_ATTR_LOG : DOUANE_NL_ATTR_NOLOG)) goto fail;
  }
  for(j = 0; j < count; j++)
  {
    i = count - j;
    nla_nest_end(ms.msg, attrptr_stack->a[i]);
  }

  if(0>_dnl_send(&ms)) goto fail;

  kfree_rcu(attrptr_stack, rcu);

  LOG_DEBUG(stack_id, "complete");
  return 0;

prefail:
  LOG_ERR(stack_id, "prefail");
  return -1;

fail:
  if(attrptr_stack) kfree_rcu(attrptr_stack, rcu);

  LOG_ERR(stack_id, "error");
  return _dnl_clean(&ms);
}

////////////////////

// An echo command, receives a message, prints it and sends another message back
static int _dnl_comm_echo(struct sk_buff *skb_in, struct genl_info *info)
{
  struct MSGSTATE ms = { 0, 0 };
  struct nlattr * tmp_attr;
  char * mydata = 0;
  uint32_t stack_id = _dnl_stackid();

  LOG_DEBUG(stack_id, "start");

  tmp_attr = info->attrs[DOUANE_NL_ATTR_ECHOBODY];
  if(tmp_attr)
  {
    mydata = (char*)nla_data(tmp_attr);
    if(!mydata) goto fail;

    LOG_DEBUG(stack_id, "received: %s\n", mydata);

    if(!nl_rfns) goto fail;
    nl_rfns->recv_echo(mydata, stack_id);
  }

  // a list built with recursive enumeration...
  if(info->attrs[DOUANE_NL_ATTR_ECHONESTED])
  {
    struct nlattr * curr_attrs[DOUANE_NL_ATTR_MAX +1]; // +1 because attrib 0 is nl_skipped

    memcpy(curr_attrs, info->attrs, sizeof(curr_attrs));

    LOG_DEBUG(stack_id, "received list");

    do {
      int rc = 0;

      tmp_attr = curr_attrs[DOUANE_NL_ATTR_ECHONESTED];
      if(!tmp_attr) { LOG_DEBUG(stack_id, "end of list"); break; }

      memset(curr_attrs, 0, sizeof(curr_attrs));
      rc = nla_parse_nested(curr_attrs, DOUANE_NL_ATTR_MAX, tmp_attr, dnl_policy, NULL);
      if(rc!=0) { LOG_ERR(stack_id, "!nla_parse_nested"); break; }

      tmp_attr = curr_attrs[DOUANE_NL_ATTR_ECHOBODY];
      if(!tmp_attr) { LOG_ERR(stack_id, "!DOUANE_NL_ATTR_ECHOBODY"); break; }

      mydata = (char*)nla_data(tmp_attr);
      if(!mydata) { LOG_ERR(stack_id, "!nla_data"); break; }

      if(!nl_rfns) goto fail;
      nl_rfns->recv_echo(mydata, stack_id);
    } while(true);
  }

  LOG_DEBUG(stack_id, "complete");
  return 0;

fail:
  LOG_ERR(stack_id, "error");
  return _dnl_clean(&ms);
}

static int _dnl_comm_event(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = _dnl_stackid();
  LOG_DEBUG(stack_id, "called");
  return 0;
}

static int _dnl_comm_log(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = _dnl_stackid();

  LOG_DEBUG(stack_id, "start");

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
  {
    LOG_ERR(stack_id, "rejected from unprivileged process");
    return 0;
  }

  if (info->attrs[DOUANE_NL_ATTR_ENABLE] && nl_rfns)
  {
    nl_rfns->logging_set(true, stack_id);
    LOG_DEBUG(stack_id, "logging enabled");
  }
  if (info->attrs[DOUANE_NL_ATTR_DISABLE] && nl_rfns)
  {
    nl_rfns->logging_set(false, stack_id);
    LOG_DEBUG(stack_id, "logging disabled");
  }

  if (info->attrs[DOUANE_NL_ATTR_QUERY])
  {
    struct MSGSTATE ms = { 0, 0 };
    bool logging = false;
    nl_rfns->logging_get(&logging, stack_id);
    if(0>_dnl_prep(&ms, DOUANE_NL_COMM_LOG)) goto failquery;
    if(0>nla_put_flag(ms.msg, logging ? DOUANE_NL_ATTR_ENABLE : DOUANE_NL_ATTR_DISABLE)) goto failquery;
    if(0>_dnl_send(&ms)) goto failquery;
    return 0;

failquery:
    LOG_ERR(stack_id, "DOUANE_NL_ATTR_QUERY error");
    _dnl_clean(&ms);
  }

  return 0;
}

static int _dnl_comm_mode(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = _dnl_stackid();

  LOG_DEBUG(stack_id, "start");

  if (info->attrs[DOUANE_NL_ATTR_HELLO])
  {
    nl_port = info->snd_portid;
    nl_net = genl_info_net(info);
    LOG_DEBUG(stack_id, "daemon connection accepted %d %p\n", nl_port, nl_net);
  }
  if (info->attrs[DOUANE_NL_ATTR_ENABLE] && nl_rfns)
  {
    nl_rfns->enable_set(true, stack_id);
    LOG_DEBUG(stack_id, "filtering enabled");
  }
  if (info->attrs[DOUANE_NL_ATTR_DISABLE] && nl_rfns)
  {
    nl_rfns->enable_set(false, stack_id);
    LOG_DEBUG(stack_id, "filtering disabled");
  }
  if (info->attrs[DOUANE_NL_ATTR_QUERY] && nl_rfns)
  {
    struct MSGSTATE ms = { 0, 0 };
    bool enable = false;
    LOG_DEBUG(stack_id, "DOUANE_NL_ATTR_QUERY");
    nl_rfns->enable_get(&enable, stack_id);
    if(0>_dnl_prep(&ms, DOUANE_NL_COMM_MODE)) goto failquery;
    if(0>nla_put_flag(ms.msg, enable ? DOUANE_NL_ATTR_ENABLE : DOUANE_NL_ATTR_DISABLE)) goto failquery;
    if(0>_dnl_send(&ms)) goto failquery;
    return 0;

failquery:
    LOG_ERR(stack_id, "DOUANE_NL_ATTR_QUERY error");
    _dnl_clean(&ms);
  }
  if (info->attrs[DOUANE_NL_ATTR_BYE])
  {
    nl_port = 0;
    nl_net = 0;
    LOG_DEBUG(stack_id, "daemon disconnected");
  }

  return 0;
}

static int _dnl_comm_rule(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = _dnl_stackid();

  LOG_DEBUG(stack_id, "start");

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
  {
    LOG_ERR(stack_id, "rejected from unprivileged process");
    return 0;
  }

  // model after _dnl_comm_echo ?

  {
    uint32_t u32proc = 0, u32prot = 0, u32user = 0, u32group = 0;
    char *szdev = "";
    struct nlattr *na = 0;
    struct douane_rule rule;

    memset(&rule, 0, sizeof(struct douane_rule));

    if ((na=info->attrs[DOUANE_NL_ATTR_PROCESS_ID])) u32proc=nla_get_u32(na);
    if ((na=info->attrs[DOUANE_NL_ATTR_PROTOCOL_ID])) u32prot=nla_get_u32(na);
    if ((na=info->attrs[DOUANE_NL_ATTR_USER_ID])) u32user=nla_get_u32(na);
    if ((na=info->attrs[DOUANE_NL_ATTR_GROUP_ID])) u32group=nla_get_u32(na);
    if ((na=info->attrs[DOUANE_NL_ATTR_PROCESS_STR])) strncpy(rule.process_path, nla_data(na), PATH_LENGTH);
    if ((na=info->attrs[DOUANE_NL_ATTR_DEVICE_STR])) szdev=nla_data(na); // not a copy

    rule.allowed = info->attrs[DOUANE_NL_ATTR_ALLOW] ? true : false;
    rule.allowed = info->attrs[DOUANE_NL_ATTR_BLOCK] ? false : true;
    //rule.enabled = info->attrs[DOUANE_NL_ATTR_ENABLE] ? true : false;
    //rule.enabled = info->attrs[DOUANE_NL_ATTR_DISABLE] ? false : true;
    //rule.log = info->attrs[DOUANE_NL_ATTR_LOG] ? true : false;
    //rule.log = info->attrs[DOUANE_NL_ATTR_NOLOG] ? false : true;

  /*
      if (info->attrs[DOUANE_NL_ATTR_REMOVE])
      {
      }
  */
    if(nl_rfns) nl_rfns->rule_add(&rule, stack_id);
  }

  return 0;
}

static int _dnl_comm_rules(struct sk_buff *skb_in, struct genl_info *info)
{
  uint32_t stack_id = _dnl_stackid();

  LOG_DEBUG(stack_id, "start");

  if(!netlink_capable(skb_in, CAP_NET_ADMIN))
  {
    LOG_ERR(stack_id, "rejected from unprivileged process");
    return 0;
  }

  if (info->attrs[DOUANE_NL_ATTR_CLEAR] && nl_rfns)
  {
    nl_rfns->rules_clear(stack_id);
  }

  if (info->attrs[DOUANE_NL_ATTR_QUERY] && nl_rfns)
  {
    nl_rfns->rules_query(stack_id);
  }

  return 0;
}

///////

// command/handler mapping
struct genl_ops dnl_ops[] = {
  { .cmd = DOUANE_NL_COMM_ECHO, .doit = _dnl_comm_echo, },
  { .cmd = DOUANE_NL_COMM_LOG, .doit = _dnl_comm_log, },
  { .cmd = DOUANE_NL_COMM_MODE, .doit = _dnl_comm_mode, .flags = GENL_ADMIN_PERM, },
  { .cmd = DOUANE_NL_COMM_RULE, .doit = _dnl_comm_rule, },
  { .cmd = DOUANE_NL_COMM_RULES, .doit = _dnl_comm_rules, },
  { .cmd = DOUANE_NL_COMM_EVENT, .doit = _dnl_comm_event, },
};

//family definition
static struct genl_family dnl_family __ro_after_init = {
  .name = DOUANE_NL_NAME,
  .version = DOUANE_NL_VERSION,
  .hdrsize = 0,
  .maxattr = DOUANE_NL_ATTR_MAX,
  .policy = dnl_policy,
  .ops = dnl_ops,
  .n_ops = DOUANE_NL_COMM_MAX,
};

int dnl_init(struct dnl_recvfns * rfns)
{
  int rc;

  if ((rc = genl_register_family(&dnl_family)) != 0)
  {
    LOG_ERR(0, "genl_register_family failed %d", rc);
    return -1;
  }

  nl_rfns = rfns;

  return 0;
}

void dnl_exit(void)
{
  dnl_send_bye(0);

  nl_rfns = NULL;

  if (genl_unregister_family(&dnl_family) != 0)
  {
    LOG_ERR(0, "genl_unregister_family failed");
  }
}
