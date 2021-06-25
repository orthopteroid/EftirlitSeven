// eftirlit7 (gpl2) - orthopteroid@gmail.com

#include "crc32.h"
#include "defs.h"

#define E7X_NAME(x)       const char * ENL_NAME = #x;
#define E7X_VERSION(x)    const int ENL_VERSION = x;
#define E7X_CONST(x, y, z)
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

// const ordinals
enum {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)     _##x,
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
  _E7C_COUNT,
};

const char * def_const_name[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)  #x ,
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

uint32_t def_const_value[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)  (uint32_t)z ,
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

const char * def_const_alias[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)  y ,
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

uint32_t def_const_alias_hash[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)  0,
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

// flag ordinals
enum {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)  _##x,
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)
  #include "defs.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
  _E7F_COUNT,
};


uint32_t def_flag_value[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)     (uint32_t)z,
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

const char * def_flag_name[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)  #x ,
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

const char * def_flag_alias[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)  y ,
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

uint32_t def_flag_alias_hash[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)     0,
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

// attribute policies and types
struct nla_policy def_policy[] = {
  /*ENL_ATTR_UNSUPP*/ { }, // attribute 0 is not supported in netlink
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)  { .type = t },
  #include "defs.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

// command names
const char * def_comm_name[] = {
  "ENL_COMM_UNSUPP", // command 0 is not supported in netlink
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)
  #define E7X_COMM(x)     #x ,
  #define E7X_ATTR(x, t)
  #include "defs.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

// attribute names
const char * def_attrib_name[] = {
  "ENL_ATTR_UNSUPP", // attribute 0 is not supported in netlink
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y, z)
  #define E7X_FLAG(x, y, z)
  #define E7X_COMM(x)
  #define E7X_ATTR(x, t)  #x ,
  #include "defs.x"
  #undef E7X_NAME
  #undef E7X_VERSION
  #undef E7X_CONST
  #undef E7X_FLAG
  #undef E7X_COMM
  #undef E7X_ATTR
};

const char * def_protname(uint32_t protocol)
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
    case E7C_IP_ANY: return "ANY";
    default: return 0;
  }
}

const char * def_actionname(uint32_t action)
{
  switch(action)
  {
    case 0/*NF_DROP*/: return "NF_DROP";
    case 1/*NF_ACCEPT*/: return "NF_ACCEPT";
    case 2/*NF_STOLEN*/: return "NF_STOLEN";
    case 3/*NF_QUEUE*/: return "NF_QUEUE";
    case 4/*NF_REPEAT*/: return "NF_REPEAT";
    default: return "NF_?";
  }
}

///////////////////////

int def_flag_alias_idx(const char* alias)
{
  uint32_t h;
  int i;

  if(!alias) return -1;
  h = crc32(alias);

  for(i=0; i<_E7F_COUNT; i++)
    if(h==def_flag_alias_hash[i]) return i;
  return -1;
}

const char* def_flag_name_str(int f)
{
  if(f<_E7F_COUNT)
    return def_flag_name[f];
  return 0;
}

const char* def_const_name_str(uint32_t c)
{
  int i;
  for(i=0; i<_E7C_COUNT; i++)
    if(c==def_const_value[i]) return def_const_name[i];
  return 0;
}

uint32_t def_const_alias_value(const char* alias)
{
  uint32_t h;
  int i;

  if(!alias) return -1;
  h = crc32(alias);

  for(i=0; i<_E7C_COUNT; i++)
    if(h==def_const_alias_hash[i]) return def_const_value[i];
  return -1;
}

int def_init(void)
{
  int i = 0, j = 0;

  for(i=0; i<_E7F_COUNT; i++)
    def_flag_alias_hash[i] = crc32(def_flag_alias[i]);

  for(i=0; i<_E7F_COUNT; i++)
    for(j=i+1; j<_E7F_COUNT; j++)
      if(def_flag_alias_hash[i]==def_flag_alias_hash[j]) return -1;

  for(i=0; i<_E7C_COUNT; i++)
    def_const_alias_hash[i] = crc32(def_const_alias[i]);

  for(i=0; i<_E7C_COUNT; i++)
    for(j=i+1; j<_E7C_COUNT; j++)
      if(def_const_alias_hash[i]==def_const_alias_hash[j]) return -1;

  return 0;
}

void def_exit(void)
{
}
