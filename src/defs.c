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

bool def_protname(const char **sz_out, uint32_t protocol)
{
  switch((int32_t)protocol)
  {
    case IPPROTO_ICMP: *sz_out = "ICMP"; break;
    case IPPROTO_IGMP: *sz_out = "IGMP"; break;
    case IPPROTO_IPIP: *sz_out = "IPIP"; break;
    case IPPROTO_TCP: *sz_out = "TCP"; break;
    case IPPROTO_EGP: *sz_out = "EGP"; break;
    case IPPROTO_PUP: *sz_out = "PUP"; break;
    case IPPROTO_UDP: *sz_out = "UDP"; break;
    case IPPROTO_IDP: *sz_out = "IDP"; break;
    case IPPROTO_TP: *sz_out = "TP"; break;
    case IPPROTO_DCCP: *sz_out = "DCCP"; break;
    case IPPROTO_IPV6: *sz_out = "IPV6"; break;
    case IPPROTO_RSVP: *sz_out = "RSVP"; break;
    case IPPROTO_GRE: *sz_out = "GRE"; break;
    case IPPROTO_ESP: *sz_out = "ESP"; break;
    case IPPROTO_AH: *sz_out = "AH"; break;
    case IPPROTO_MTP: *sz_out = "MTP"; break;
    case IPPROTO_BEETPH: *sz_out = "BEETPH"; break;
    case IPPROTO_ENCAP: *sz_out = "ENCAP"; break;
    case IPPROTO_PIM: *sz_out = "PIM"; break;
    case IPPROTO_COMP: *sz_out = "COMP"; break;
    case IPPROTO_SCTP: *sz_out = "SCTP"; break;
    case IPPROTO_UDPLITE: *sz_out = "UDPLITE"; break;
    case IPPROTO_MPLS: *sz_out = "MPLS"; break;
    case IPPROTO_RAW: *sz_out = "RAW"; break;
    case E7C_IP_ANY: *sz_out = "ANY"; break;
    default: return false;
  }
  return true;
}

bool def_actionname(const char **sz_out, uint32_t action)
{
  switch(action)
  {
    case 0/*NF_DROP*/: *sz_out = "NF_DROP"; break;
    case 1/*NF_ACCEPT*/: *sz_out = "NF_ACCEPT"; break;
    case 2/*NF_STOLEN*/: *sz_out = "NF_STOLEN"; break;
    case 3/*NF_QUEUE*/: *sz_out = "NF_QUEUE"; break;
    case 4/*NF_REPEAT*/: *sz_out = "NF_REPEAT"; break;
    default: return false;
  }
  return true;
}

///////////////////////

bool def_flag_alias_idx(uint32_t *i_out, const char* alias)
{
  uint32_t h;
  int i;

  if(!i_out) return false;
  if(!alias) return false;
  h = e7_crc32(alias);

  for(i=0; i<_E7F_COUNT; i++)
    if(h==def_flag_alias_hash[i]) { *i_out = i; return true; }

  return false;
}

bool def_flag_name_str(const char** sz_out, uint32_t f)
{
  if(!sz_out) return false;

  if(f<_E7F_COUNT) { *sz_out = def_flag_name[f]; return true; }

  return false;
}

bool def_const_name_str(const char **sz_out, uint32_t c)
{
  int i;

  if(!sz_out) return false;

  for(i=0; i<_E7C_COUNT; i++)
    if(c==def_const_value[i]) { *sz_out = def_const_name[i]; return true; }

  return false;
}

bool def_const_alias_value(uint32_t *v_out, const char* alias)
{
  uint32_t h;
  int i;

  if(!v_out) return false;
  if(!alias) return false;
  h = e7_crc32(alias);

  for(i=0; i<_E7C_COUNT; i++)
    if(h==def_const_alias_hash[i]) { *v_out = def_const_value[i]; return true; }

  return false;
}

int def_init(void)
{
  int i = 0, j = 0;

  for(i=0; i<_E7F_COUNT; i++)
    def_flag_alias_hash[i] = e7_crc32(def_flag_alias[i]);

  for(i=0; i<_E7F_COUNT; i++)
    for(j=i+1; j<_E7F_COUNT; j++)
      if(def_flag_alias_hash[i]==def_flag_alias_hash[j]) return -1;

  for(i=0; i<_E7C_COUNT; i++)
    def_const_alias_hash[i] = e7_crc32(def_const_alias[i]);

  for(i=0; i<_E7C_COUNT; i++)
    for(j=i+1; j<_E7C_COUNT; j++)
      if(def_const_alias_hash[i]==def_const_alias_hash[j]) return -1;

  return 0;
}

void def_exit(void)
{
}
