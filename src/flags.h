#ifndef _FLAGS_H_
#define _FLAGS_H_

// const enumeration
enum {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y)     x,
  #define E7X_FLAG(x, y, z)
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

// flag enumeration
enum {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x, y)
  #define E7X_FLAG(x, y, z)  x,
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

extern uint32_t flag_value[];

extern const char* flag_name[];

int flag_lookup(const char* name);

int flag_init(void);
void flag_exit(void);

#endif // _FLAGS_H_
