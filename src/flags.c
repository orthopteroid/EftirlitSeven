// eftirlit7 (gpl3) - orthopteroid@gmail.com

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

#include "crc32.h"

uint32_t flag_value[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)     0,
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

const char * flag_name[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)  #x ,
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

uint32_t flag_hash[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)     0,
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

int flag_lookup(const char* name)
{
  uint32_t h = crc32(name);
  int i;
  for(i=0; i<sizeof(flag_value); i++)
    if(h==flag_hash[i]) return i;
  return -1;
}

int flag_init()
{
  int i = 0;
  for(i=0; i<sizeof(flag_value); i++)
    flag_hash[i] = crc32(flag_name[i]);
}

void flag_exit(void)
{
}
