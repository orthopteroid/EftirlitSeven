// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

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
#include "douane.h"
#include "ksc.h"
#include "asc.h"
#include "rules.h"
#include "netlink.h"
#include "flags.h"

#include "prot_tcp.h"
#include "prot_udp.h"

// fwd decls
static unsigned int douane__nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct nf_hook_ops netfilter_config = {
  .hook     = douane__nfhandler,
  .hooknum  = NF_IP_LOCAL_OUT,
  .pf       = NFPROTO_IPV4,
  .priority = NF_IP_PRI_LAST,
};

///////////////

static char * douane__lookup_protname(const int protocol)
{
  switch(protocol)
  {
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_IGMP: return "IGMP";
    case IPPROTO_IPIP: return "IPIP";
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_EGP: return "EGP";
    case IPPROTO_PUP: return "PUP";
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_IDP: return "IDP";
    case IPPROTO_TP: return "TP";
    case IPPROTO_DCCP: return "DCCP";
    case IPPROTO_IPV6: return "IPV6";
    case IPPROTO_RSVP: return "RSVP";
    case IPPROTO_GRE: return "GRE";
    case IPPROTO_ESP: return "ESP";
    case IPPROTO_AH: return "AH";
    case IPPROTO_MTP: return "MTP";
    case IPPROTO_BEETPH: return "BEETPH";
    case IPPROTO_ENCAP: return "ENCAP";
    case IPPROTO_PIM: return "PIM";
    case IPPROTO_COMP: return "COMP";
    case IPPROTO_SCTP: return "SCTP";
    case IPPROTO_UDPLITE: return "UDPLITE";
    case IPPROTO_MPLS: return "MPLS";
    case IPPROTO_RAW: return "RAW";
    default: return "UNKNOWN";
  }
}

static bool douane__valid_nfaction(int action)
{
  switch(action)
  {
    case NF_DROP:
    case NF_ACCEPT:
    case NF_STOLEN:
    case NF_QUEUE:
    case NF_REPEAT:
      return true;
    default:
      return false;
  }
}

static char * douane__lookup_nfaction(int action)
{
  switch(action)
  {
    case NF_DROP: return "NF_DROP";
    case NF_ACCEPT: return "NF_ACCEPT";
    case NF_STOLEN: return "NF_STOLEN";
    case NF_QUEUE: return "NF_QUEUE";
    case NF_REPEAT: return "NF_REPEAT";
    default: return "IGNORE";
  }
}

static void douane__parse_protocol(
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

static unsigned int douane__nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr * ip_header = NULL;
  struct psi psi;
  uint32_t packet_id;
  int action = 0;

  memset(&psi, 0, sizeof(struct psi));

  get_random_bytes(&packet_id, sizeof(packet_id));

  switch(flag_value[E7F_MODE])
  {
    case E7C_LOCKDOWN: return NF_DROP;
    case E7C_DISABLED: return NF_ACCEPT;
    case E7C_ENABLED: break;
    default: break;
  }

  if (mod_isstopping())
  {
    LOG_DEBUG(packet_id, "module is stopping - NF_ACCEPT)");
    return NF_ACCEPT;
  }

  if (skb == NULL)
  {
    action = flag_value[E7F_FAILPATH_ACTION];
    if (douane__valid_nfaction(action))
    {
      LOG_ERR(packet_id, "socket buffer is null - %s", douane__lookup_nfaction(action));
      return action;
    }
    return NF_ACCEPT; // review
  }

  ip_header = ip_hdr(skb);
  if (ip_header == NULL)
  {
    action = flag_value[E7F_FAILPATH_ACTION];
    if (douane__valid_nfaction(action))
    {
      LOG_ERR(packet_id, "ip_header is null - %s", douane__lookup_nfaction(action));
      return action;
    }
    return NF_ACCEPT; // review
  }

  LOG_DEBUG(packet_id, "~~~ new %s packet", douane__lookup_protname(ip_header->protocol));

  {
    bool process_identified = false;
    bool protocol_identified = false;

    douane__parse_protocol(&protocol_identified, &process_identified, ip_header, &psi, packet_id, priv, skb, state);

    if (!protocol_identified)
    {
      action = flag_value[E7F_UNKN_PROTOCOL_ACTION];
      if (douane__valid_nfaction(action))
      {
        LOG_DEBUG(packet_id, "unhandled protocol - %s", douane__lookup_nfaction(action));
        return action;
      }
      return NF_ACCEPT; // review
    }

    if (!process_identified)
    {
      action = flag_value[E7F_UNKN_PROCESS_ACTION];
      if (douane__valid_nfaction(action))
      {
        LOG_DEBUG(packet_id, "unidentfied process PID %d '%s' - %s", psi.pid, psi.process_path, douane__lookup_nfaction(action));
        return action;
      }
      return NF_ACCEPT; // review
    }
  }

  {
    struct rule_struct rule;

    if (0>rules_search(&rule, psi.process_path, packet_id))
    {
      action = flag_value[E7F_RULE_QUERY_ACTION];
      if (douane__valid_nfaction(action))
      {
        LOG_DEBUG(packet_id, "rules_search failed for %s - %s", psi.process_path, douane__lookup_nfaction(action));

        if((flag_value[E7F_RULE_QUERY_EVENTS]==E7C_ENABLED) && enl_is_connected())
          enl_send_event(E7C_PENDING, ip_header->protocol, psi.process_path, packet_id);

        return action;
      }
      return NF_ACCEPT; // review
    }

    if (rule.allowed)
    {
      LOG_DEBUG(packet_id, "allowed %s - NF_ACCEPT", psi.process_path);

      if((flag_value[E7F_RULE_ACCEPT_EVENTS]==E7C_ENABLED) && enl_is_connected())
        enl_send_event(E7C_ALLOW, ip_header->protocol, psi.process_path, packet_id);

      return NF_ACCEPT;
    }
    else
    {
      LOG_DEBUG(packet_id, "blocked %s - NF_DROP", psi.process_path);

      if((flag_value[E7F_RULE_DROP_EVENTS]==E7C_ENABLED) && enl_is_connected())
        enl_send_event(E7C_BLOCK, ip_header->protocol, psi.process_path, packet_id);

      return NF_DROP;
    }
  }
}

//////////////////

int douane_init(void)
{
  nf_register_net_hook(&init_net, &netfilter_config);
  prot_tcp_init();

  LOG_INFO(0, "early filter action - %s", douane__lookup_nfaction(flag_value[E7F_MODE]));

  return 0;
}

void douane_exit(void)
{
  prot_tcp_exit();
  nf_unregister_net_hook(&init_net, &netfilter_config);
}
