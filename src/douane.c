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
#include "ksc.h"
#include "asc.h"
#include "rules.h"

#include "prot_tcp.h"
#include "prot_udp.h"

// fwd decls
static unsigned int douane_nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static struct nf_hook_ops netfilter_config = {
  .hook     = douane_nfhandler,
  .hooknum  = NF_IP_LOCAL_OUT,
  .pf       = NFPROTO_IPV4,
  .priority = NF_IP_PRI_LAST,
};

static bool enabled = false;
static bool logging = true;

///////////////

void douane_enable_set(bool value, const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "enable change to %s", value ? "enable" : "disable");

  enabled = value;
}

void douane_enable_get(bool * value_out, const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "get enable value of %s", enabled ? "enable" : "disable");

  *value_out = enabled;
}

void douane_logging_set(bool value, const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "logging change to %s", value ? "enable" : "disable");

  logging = value;
}

void douane_logging_get(bool * value_out, const uint32_t packet_id)
{
  LOG_DEBUG(packet_id, "get logging value of %s", logging ? "enable" : "disable");

  *value_out = logging;
}

char * douane_lookup_protname(const int protocol)
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

///////////////

static unsigned int douane_nfhandler(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  struct iphdr * ip_header = NULL;
  struct rule_struct existing_rule;
  bool process_identified = false;
  struct psi psi;
  uint32_t packet_id;

  memset(&psi, 0, sizeof(struct psi));

  get_random_bytes(&packet_id, sizeof(packet_id));

  LOG_DEBUG(packet_id, "~~~ new packet");

  if (mod_isstopping())
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (module is stopping)");
    return NF_ACCEPT;
  }

  if (skb == NULL)
  {
    LOG_ERR(packet_id, "NF_ACCEPT (socket buffer is null)");
    return NF_ACCEPT;
  }

  ip_header = ip_hdr(skb);
  if (ip_header == NULL)
  {
    LOG_ERR(packet_id, "NF_ACCEPT (ip_header is null)");
    return NF_ACCEPT;
  }
  LOG_DEBUG(packet_id, "packet %s, %s",
    douane_lookup_protname(ip_header->protocol),
    in_softirq() ? "in_softirq()" : "!in_softirq()"
  );

  switch(ip_header->protocol)
  {
    case IPPROTO_UDP:
      process_identified = prot_udp_parse(&psi, packet_id, priv, skb, state);
      break;

    case IPPROTO_TCP:
      process_identified = prot_tcp_parse(&psi, packet_id, priv, skb, state);
      break;

    default:
      LOG_ERR(packet_id, "NF_ACCEPT (ip_header->protocol fallthrough)");
      return NF_ACCEPT;
  }

  if (!enabled)
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (filtering disabled. process %s)", psi.process_path);
    return NF_ACCEPT;
  }

  if (!process_identified)
  {
    LOG_DEBUG(packet_id, "NF_ACCEPT (unprocess_identified %s)", psi.process_path);
    return NF_ACCEPT;
  }

  LOG_DEBUG(packet_id, "searching rule for %s", psi.process_path);

  if (0>rules_search(&existing_rule, psi.process_path, packet_id))
  {
    LOG_DEBUG(packet_id, "NF_QUEUE (rules_search failed for %s)", psi.process_path);
    return NF_QUEUE;
  }

  if (!existing_rule.allowed)
  {
    LOG_DEBUG(packet_id, "NF_DROP (block %s)", psi.process_path);
    return NF_DROP;
  }

  LOG_DEBUG(packet_id, "NF_ACCEPT (allow %s)", psi.process_path);
  return NF_ACCEPT;
}

//////////////////

int douane_init(void)
{
  nf_register_net_hook(&init_net, &netfilter_config);
  prot_tcp_init();
  return 0;
}

void douane_exit(void)
{
  prot_tcp_exit();
  nf_unregister_net_hook(&init_net, &netfilter_config);
}
