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
#include "netfilter.h"
#include "ksc.h"
#include "asc.h"
#include "rules.h"
#include "netlink.h"
#include "defs.h"

#include "prot_tcp.h"
#include "prot_udp.h"

// fwd decls
static unsigned int enf__nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct nf_hook_ops netfilter_config = {
  .hook     = enf__nfhandler,
  .hooknum  = NF_IP_LOCAL_OUT,
  .pf       = NFPROTO_IPV4,
  .priority = NF_IP_PRI_LAST,
};

///////////////

int get_mode_action(const char * message, uint32_t packet_id)
{
  switch(def_flag_value[E7F_MODE])
  {
    case E7C_BLOCK: return NF_DROP;
    case E7C_DISABLED: return NF_ACCEPT;
    case E7C_ENABLED: return 0;
    default:
      LOG_ERR(packet_id, "%s - disabled", message);
      def_flag_value[E7F_MODE] = E7C_DISABLED;
      return NF_ACCEPT;
  }
}

int get_action(int flag, const char * message, uint32_t packet_id)
{
  switch(def_flag_value[flag])
  {
    case E7C_ALLOW: return NF_ACCEPT;
    case E7C_BLOCK: return NF_DROP;
    default:
      LOG_ERR(packet_id, "%s - fixed", message);
      def_flag_value[flag] = E7C_ALLOW;
      return NF_ACCEPT;
  }
}

static void enf__parse_protocol(
  bool * prot_out, bool * proc_out, struct iphdr * ip_header,
  struct psi *psi_out, uint32_t packet_id, void *priv, struct sk_buff *skb, const struct nf_hook_state *state
)
{
  *prot_out = *proc_out = true; // assume identified
  switch(ip_header->protocol)
  {
    case IPPROTO_UDP:
      *proc_out = prot_udp_parse(psi_out, packet_id, priv, skb, state);
      break;

    case IPPROTO_TCP:
      *proc_out = prot_tcp_parse(psi_out, packet_id, priv, skb, state);
      break;

    default:
      *prot_out = false; // protocol unidentified
  }
}

///////////////

// douane: basic nfhandler structure has been factored and protocols broken out
static unsigned int enf__nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr * ip_header = NULL;
  const char * szprot = 0, * szaction = 0;
  int nfoperation = NF_DROP; // 0
  uint32_t packet_id;
  struct psi psi;
  int action = 0;

  memset(&psi, 0, sizeof(struct psi));

  get_random_bytes(&packet_id, sizeof(packet_id));

  action = get_mode_action("firewall mode invalid state", packet_id);
  if(action) return action;

  if (mod_isstopping())
  {
    LOG_DEBUG(packet_id, "module is stopping - NF_ACCEPT)");
    return NF_ACCEPT;
  }

  if (skb == NULL)
  {
    return get_action(E7F_FAILPATH_ACTION, "socket buffer failpath config invalid", packet_id);
  }

  ip_header = ip_hdr(skb);
  if (ip_header == NULL)
  {
    return get_action(E7F_FAILPATH_ACTION, "ip_header failpath config invalid", packet_id);
  }

  szprot = def_protname(ip_header->protocol);

  LOG_DEBUG(packet_id, "~~~ new %s packet", szprot ? szprot : "?");

  {
    bool process_identified = false;
    bool protocol_identified = false;

    enf__parse_protocol(&protocol_identified, &process_identified, ip_header, &psi, packet_id, priv, skb, state);

    if (!protocol_identified)
    {
      nfoperation = get_action(E7F_UNKN_PROTOCOL_ACTION, "unhandled protocol failpath config invalid", packet_id);
      szaction = def_actionname(nfoperation);
      LOG_DEBUG(packet_id, "unhandled protocol %s - %s", szprot ? szprot : "?", szaction ? szaction : "?");
      return nfoperation;
    }

    if (!process_identified)
    {
      nfoperation = get_action(E7F_UNKN_PROCESS_ACTION, "unhandled protocol failpath config invalid", packet_id);
      szaction = def_actionname(nfoperation);
      LOG_DEBUG(packet_id, "unidentfied process PID %d '%s' - %s", psi.pid, psi.process_path, szaction ? szaction : "?");
      return nfoperation;
    }
  }

  {
    struct rule_struct rule;

    if (!rules_search(&rule, ip_header->protocol, psi.process_path, packet_id))
    {
      nfoperation = get_action(E7F_RULE_NORULE_ACTION, "unhandled protocol failpath config invalid", packet_id);
      szaction = def_actionname(nfoperation);
      LOG_DEBUG(packet_id, "rules_search failed for %s - %s", psi.process_path, szaction ? szaction : "?");

      if((def_flag_value[E7F_RULE_NORULE]==E7C_ENABLED) && enl_is_connected())
        enl_send_event(E7C_PENDING, ip_header->protocol, psi.process_path, packet_id);

      return nfoperation;
    }

    if (rule.allowed)
    {
      LOG_DEBUG(packet_id, "allowed %s - NF_ACCEPT", psi.process_path);

      if((def_flag_value[E7F_RULE_ACCEPTS]==E7C_ENABLED) && enl_is_connected())
        enl_send_event(E7C_ALLOW, ip_header->protocol, psi.process_path, packet_id);

      return NF_ACCEPT;
    }
    else
    {
      LOG_DEBUG(packet_id, "blocked %s - NF_DROP", psi.process_path);

      if((def_flag_value[E7F_RULE_DROPS]==E7C_ENABLED) && enl_is_connected())
        enl_send_event(E7C_BLOCK, ip_header->protocol, psi.process_path, packet_id);

      return NF_DROP;
    }
  }
}

//////////////////

int enf_init(void)
{
  int action = 0;

  nf_register_net_hook(&init_net, &netfilter_config);
  prot_tcp_init();

  action = get_mode_action("firewall mode invalid state", 0);
  LOG_INFO(0, "early filter action - %s", def_actionname(action));

  return 0;
}

void enf_exit(void)
{
  prot_tcp_exit();
  nf_unregister_net_hook(&init_net, &netfilter_config);
}
