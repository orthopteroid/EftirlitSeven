#ifndef _DEFS_H_
#define _DEFS_H_

#ifdef __cplusplus

#include <stdint.h>

// needs libnl-3-dev
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/attr.h>
#include <libnl3/netlink/errno.h> // netlink's err codes are different than regular sys codes

// needs libnl-genl-3-dev
// https://www.infradead.org/~tgr/libnl/doc/api/genl_8c_source.html
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/genl/genl.h>

#else // __cplusplus

#include <linux/types.h>

#include <linux/ip.h>             // ip_hdr()
#include <linux/netdevice.h>      // net_device
#include <linux/netfilter.h>      // nf_register_hook(), nf_unregister_hook(), nf_register_net_hook(), nf_unregister_net_hook()
#include <linux/netlink.h>        // NLMSG_SPACE(), nlmsg_put(), NETLINK_CB(), NLMSG_DATA(), NLM_F_REQUEST, netlink_unicast(), netlink_kernel_release(), nlmsg_hdr(), NETLINK_USERSOCK, netlink_kernel_create()
#include <net/genetlink.h>

#endif // __cplusplus

// const enumeration
enum {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)     x = z,
  #define E7X_FLAG(x, y, z)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)
  #include "defs.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

// flag enumeration
enum {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)  x,
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)
  #include "defs.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

// command enumeration
enum {
  ENL_COMM_UNSUPP, // command 0 is not supported in netlink
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)
  #define E7X_COMM(x)     x,
  #define E7X_ATTR(x, t)
  #include "defs.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
  __ENL_COMM_MAX,
};
#define ENL_COMM_MAX (__ENL_COMM_MAX-1)

// attribute enumeration
enum {
  ENL_ATTR_UNSUPP, // attribute 0 is not supported in netlink
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)  x,
  #include "defs.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
  __ENL_ATTR_MAX,
};
#define ENL_ATTR_MAX (__ENL_ATTR_MAX-1)

extern const char * ENL_NAME;
extern const int ENL_VERSION;

extern uint32_t def_flag_value[];
extern const char* def_flag_name[];
extern const char* def_flag_alias[];
extern uint32_t def_flag_alias_hash[];

extern const char * def_const_name[];
extern const char * def_const_alias[];
extern uint32_t def_const_alias_hash[];

extern struct nla_policy def_policy[];
extern const char * def_attrib_name[];
extern const char * def_comm_name[];

extern const char * def_protname(uint32_t protocol);
extern const char * def_actionname(uint32_t action);

int def_flag_alias_idx(const char* alias);
uint32_t def_const_alias_value(const char* alias);

const char* def_flag_name_str(int f);
const char* def_const_name_str(uint32_t c);

int def_init(void);
void def_exit(void);

#endif // _DEFS_H_
