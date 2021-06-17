// eftirlit7 (gpl3) - orthopteroid@gmail.com

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <exception>
#include <cstdint>
#include <string>
#include <list>
#include <deque>

// signals related
// https://gabrbedd.wordpress.com/2013/07/29/handling-signals-with-signalfd/
// https://man7.org/linux/man-pages/man7/epoll.7.html
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/epoll.h>

// needs libnl-3-dev
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/attr.h>
#include <libnl3/netlink/errno.h> // netlink's err codes are different than regular sys codes

// needs libnl-genl-3-dev
// https://www.infradead.org/~tgr/libnl/doc/api/genl_8c_source.html
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/genl/genl.h>

#include "crc32.h"

// reference
// https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/errno-base.h
// https://www.infradead.org/~tgr/libnl/doc/api/errno_8h_source.html
// http://charette.no-ip.com:81/programming/doxygen/netfilter/group__cb.html#ga0c50cb29c507b3d7e8bc7d76c74675f8
// https://www.infradead.org/~tgr/libnl/doc/api/group__genl.html#ga9a86a71bbba6961d41b8a75f62f9e946

// Code based on
// http://people.ee.ethz.ch/~arkeller/linux/multi/kernel_user_space_howto-3.html
// http://www.electronicsfaq.com/2014/02/generic-netlink-sockets-example-code.html
// https://lwn.net/Articles/211209/
// https://github.com/Robpol86/libnl/blob/master/example_c/scan_access_points.c

// kernelspace
// https://elixir.bootlin.com/linux/v5.4/source/include/uapi/linux/netlink.h
// https://elixir.bootlin.com/linux/v5.4/source/include/uapi/linux/genetlink.h
// https://elixir.bootlin.com/linux/v5.4/source/include/net/genetlink.h
// https://elixir.bootlin.com/linux/v5.4/source/include/net/netlink.h
// https://github.com/torvalds/linux/blob/master/net/psample/psample.c

// userspace
// https://stackoverflow.com/questions/21601521/how-to-use-the-libnl-library-to-trigger-nl80211-commands

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
  #undef E7X_COMM
  #undef E7X_ATTR
  __ENL_COMM_MAX,
};
#define ENL_COMM_MAX (__ENL_COMM_MAX-1)

// attribute enumeration
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
  #undef E7X_COMM
  #undef E7X_ATTR
};

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

constexpr uint32_t flag_hash[] = {
  #define E7X_NAME(x)
  #define E7X_VERSION(x)
  #define E7X_CONST(x)
  #define E7X_FLAG(x)     crc32(x),
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

//////////////////

//#define DEBUG_BYTES_SENT

///////////

#define E7_LOG(fmt, ...) \
  do { \
    printf("%s:%d: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    fflush(stdout); \
  } while(false)

///////////
// https://stackoverflow.com/a/42506763
template <typename F>
struct DeferExec {
    DeferExec(F&& f) : m_f(std::forward<F>(f)) {}
    ~DeferExec() { m_f(); }
    F m_f;
};

template <typename F>
DeferExec<F> defer(F&& f) {
    return DeferExec<F>(std::forward<F>(f));
};

////////////

static bool stop = false;
static struct nl_sock * nl_sk = 0;
static int nl_familyid = 0;

struct MSGSTATE
{
  struct nl_msg * msg;
  void * hdr;
};

static void e7_printrc(const char* cxt, int rc)
{
  if (rc<0)
    printf("%s: %s\n",cxt,nl_geterror(rc));
#ifdef DEBUG_BYTES_SENT
  else if (rc>0)
    printf("%s: %d bytes sent\n",cxt,rc);
#endif // DEBUG_BYTES_SENT
}

static char * e7_statename(uint32_t state)
{
  if(state > sizeof(state)) return 0;
  return enl_state_name[state];
}

static char * e7_protname(uint32_t protocol)
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
    default: return 0;
  }
}

static int e7_prep(MSGSTATE & ms, uint8_t comm) {
  ms.msg = nlmsg_alloc();
  if (ms.msg<0) return -1;

  ms.hdr = genlmsg_put(ms.msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl_familyid, 0, 0, comm, ENL_VERSION);
  if (ms.hdr) return 0;

  if (ms.msg) nlmsg_free(ms.msg);
  ms.msg = 0;
  return -1;
}

static int e7_send(MSGSTATE & ms) {
  if (!ms.msg || !ms.hdr) return -1;

  int rc = nl_send_auto(nl_sk, ms.msg); // review: "unknown or invalid cache type" error

  if (0>rc && ms.msg) nlmsg_free(ms.msg);
  ms.msg = 0;
  ms.hdr = 0;
  return rc;
}

static int e7_compose_send(int comm, int attr) {
  MSGSTATE ms;
  if(0>e7_prep(ms, comm)) return -1;
  if(0>nla_put_flag(ms.msg, attr)) return -1;
  return e7_send(ms);
}

static int e7_compose_send(int comm, int attr, const char* sz) {
  MSGSTATE ms;
  if(0>e7_prep(ms, comm)) return -1;
  if(0>nla_put_string(ms.msg, attr, sz)) return -1;
  return e7_send(ms);
}

//////////////////////

static int e7_nlcallback(struct nl_msg *msg, void *arg) {
  struct nlattr * attribs[ENL_ATTR_MAX +1]; // +1 because attrib 0 is nl_skipped
  struct nlmsghdr * nlh = NULL;
  struct genlmsghdr * gnlh = NULL;
  struct nlattr * gnlad = NULL;
  struct nlattr * a = NULL;
  uint32_t value = ~0, prot = ~0, state = ~0;
  char * szpath = 0, * szstate = 0, * szprot = 0, * szflag = 0;
  int gnlal = 0;

  if(!msg) { E7_LOG("!msg"); return 0; }
  if(!(nlh = nlmsg_hdr(msg))) { E7_LOG("!nlh"); return 0; }
  if(!(gnlh = (struct genlmsghdr *)nlmsg_data(nlh))) { E7_LOG("!gnlh"); return 0; }
  if(!(gnlad = genlmsg_attrdata(gnlh, 0))) { E7_LOG("!gnlad"); return 0; }
  if(!(gnlal = genlmsg_attrlen(gnlh, 0))) { E7_LOG("!gnlal"); return 0; }
  nla_parse(attribs, ENL_ATTR_MAX, gnlad, gnlal, enl_policy);

/*
  printf("%s ", enl_comm_name[gnlh->cmd]);
  for(int i=0; i<__ENL_ATTR_MAX; i++)
  {
    if(a = attribs[i])
    {
      if(i==ENL_ATTR_STR)       printf("%s %s", enl_attr_name[i], sz ? sz : "(null)");
      else if(i==ENL_ATTR_UINT) printf("%s %u", enl_attr_name[i], u32);
      else                      printf("%s ", enl_attr_name[i]);
    }
  }
  printf("\n");
*/
  switch(gnlh->cmd) {
  case ENL_COMM_DISCONNECT:
    stop = true;
    break;
  case ENL_COMM_GET:
    if(a = attribs[ENL_ATTR_FLAG]) szflag = nla_get_string(a);
    if(a = attribs[ENL_ATTR_VALUE]) value = nla_get_u32(a);
    E7_LOG("%s = %u", szflag ? szflag : "(null)", value);
    break;
  case ENL_COMM_EVENT:
    if(a = attribs[ENL_ATTR_STATE]) szstate = e7_statename(nla_get_u32(a));
    if(a = attribs[ENL_ATTR_PROT]) szprot = e7_protname(nla_get_u32(a));
    if(a = attribs[ENL_ATTR_PATH]) szpath = nla_get_string(a);
    E7_LOG("event state %s prot %s path %s", szstate, szprot, (szpath ? szpath : "-"));
    break;
  case ENL_COMM_QUERY:
    do {
      if(a = attribs[ENL_ATTR_STATE]) szstate = e7_statename(nla_get_u32(a));
      if(a = attribs[ENL_ATTR_PROT]) szprot = e7_protname(nla_get_u32(a));
      if(a = attribs[ENL_ATTR_PATH]) szpath = nla_get_string(a);
      E7_LOG("query state %s prot %s path %s", szstate, szprot, (szpath ? szpath : "-"));

      if(!attribs[ENL_ATTR_NESTED]) break; // end-of-list
      int rc = nla_parse_nested(attribs, ENL_ATTR_MAX, attribs[ENL_ATTR_NESTED], enl_policy);
      if(rc!=0) { E7_LOG("!nla_parse_nested"); break; }
    } while(true);
    break;
  default:
fail:
    E7_LOG("Unrecognized message");
    break;
  }

  return NL_OK;
}

///////////////////

const int fdstdin = 0;

struct CMDBUF
{
  const static int textlen = 100;
  char text[textlen +1];
  int idx = 0, len = 0;

  // return +ve length of \n terminated string
  // return -1 on error or untermed string
  int appendln_noblock(int fd)
  {
    while(idx<textlen)
    {
      int rc = read(fd, (void*)&text[idx], 1); // read single char
      if (0==rc) return -EAGAIN; // no data
      if (0>rc) return rc; // other err
      if ('\n'==text[idx])
      {
        text[idx] = '\0';
        len = idx;
        int cl = idx;
        idx = 0; // reset to buf start for next line
        return cl;
      }
      idx++;
    }
    return -EFAULT; // buffer overflow
  }

  const static int arglen = 5;
  char * arg[arglen +1];
  int argc = 0;

  const char* identifyargs()
  {
    argc = 0;
    if(0==text[0]) { return "no command"; }

    int j = 0;
    for(int i=0; i<len; i++) { if('"'==text[i]) j++; }
    if((j % 2) != 0) return "mismatched quotes";

    // 3 pass quote handling
    bool q = false;
    bool l = true;
    for(int i=0; i<len; i++) { if('"'==text[i]) q = !q; else if(!q && (' '==text[i])) text[i] = '\0'; } // null non-quoted spaces
    for(int i=0; i<len; i++) { if('"'==text[i]) text[i] = '\0'; } // null quotes
    for(int i=0; i<len; i++) { if('\0'!=text[i]) { if(l) { arg[argc++] = &text[i]; l = false; } } else l = true; } // args are leading non-nulls

    //for(int i=0; i<argc; i++) E7_LOG("arg: '%s'", arg[i]);
    return 0;
  }
};

/////////////////

void e7_parsecmd(CMDBUF & buf)
{
  MSGSTATE ms;

  const char * sz = buf.identifyargs();
  if(sz) E7_LOG("%s", sz);

  switch(crc32(buf.arg[0]))
  {
    case crc32("quit"):
      stop = true;
      break;
    case crc32("hi"):
      e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_MODE, ENL_ATTR_HELLO) );
      break;
    case crc32("bye"):
      e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_MODE, ENL_ATTR_BYE) );
      break;
    case crc32("mode"):
      if(buf.argc!=2) goto help;
      switch(crc32(buf.arg[1]))
      {
        case crc32("enable"):
          e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_MODE, ENL_ATTR_ENABLE) );
          break;
        case crc32("disable"):
          e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_MODE, ENL_ATTR_DISABLE) );
          break;
        default:
          goto help;
      }
      break;
    case crc32("query"):
      if(buf.argc!=2) goto help;
      switch(crc32(buf.arg[1]))
      {
        case crc32("mode"):
          e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_MODE, ENL_ATTR_QUERY) );
          break;
        default:
          goto help;
      }
      break;
    case crc32("hibye"):
      e7_printrc( "e7_prep", e7_prep(ms, ENL_COMM_MODE) );
      e7_printrc( "nla_put_flag", nla_put_flag(ms.msg, ENL_ATTR_HELLO) );
      e7_printrc( "nla_put_flag", nla_put_flag(ms.msg, ENL_ATTR_BYE) );
      e7_printrc( "e7_send", e7_send(ms) );
      break;
    case crc32("echo"):
      e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_ECHO, ENL_ATTR_ECHOBODY, "Hello World") );
      break;
    case crc32("echolist"):
      {
        e7_printrc( "e7_prep", e7_prep(ms, ENL_COMM_ECHO) );
        e7_printrc( "nla_put_string", nla_put_string(ms.msg, ENL_ATTR_ECHOBODY, "OUTER") );
        // a list built with recursive enumeration...
        std::deque<struct nlattr *> attrptr_stack;
        std::string inner;
        for(int z=0;z<3;z++)
        {
          // there appears to be overhead for each entry, but it seems to be around ENL_ATTR_MAX bytes. hmmm.
          inner = inner + "INNER ";
          attrptr_stack.push_front( nla_nest_start(ms.msg, ENL_ATTR_ECHONESTED | NLA_F_NESTED) ); // | NESTED required with ubuntu libnl 3.2.29
          e7_printrc( "nla_put_string", nla_put_string(ms.msg, ENL_ATTR_ECHOBODY, inner.c_str()) );
        }
        while(!attrptr_stack.empty())
        {
          nla_nest_end(ms.msg, attrptr_stack.front());
          attrptr_stack.pop_front();
        }
        e7_printrc( "e7_send", e7_send(ms) );
      }
      break;
    default:
help:
      printf("quit, hi, by, hibye, echo, echolist, mode ( enable | disable ), query mode\n");
  }
}


/////////////////

struct EPOLL
{
  const static int timeout = -1;
  const static int EPOLL_MAX_EVENTS = 10;

  struct epoll_event evt, events[EPOLL_MAX_EVENTS];
  sigset_t *sigset = 0;
  int fdepoll = 0;

  EPOLL(sigset_t *ss) { assert(0<(fdepoll = epoll_create1(0))); sigset = ss; evt.events = EPOLLIN; }
  virtual ~EPOLL() { close(fdepoll); fdepoll=0; }

  void addfd(int fd) { evt.data.fd = fd; assert(!epoll_ctl(fdepoll, EPOLL_CTL_ADD, fd, &evt)); }
  int pwait() { return epoll_pwait(fdepoll, events, EPOLL_MAX_EVENTS, timeout, sigset); }
};

int main(void)
{
  int rc = 0;

  E7_LOG("nice");

  errno = 0;
  rc = nice(-20);
  if(0>rc && errno!=0) { E7_LOG("unable to change daemon priority. not root?"); return -1; }

  E7_LOG("configure sighandler");

  sigset_t sigset;
  rc = sigemptyset(&sigset) | sigaddset(&sigset, SIGINT) | sigprocmask(SIG_BLOCK, &sigset, NULL);
  assert(!rc);

  int fdsig = signalfd(-1, &sigset, 0);
  assert(0<fdsig);
  auto close_fdsig = defer([&](){ close(fdsig); fdsig=0; });

  E7_LOG("configure netlink");

  nl_sk = nl_socket_alloc();
  assert(nl_sk);
  auto close_nlsk = defer([&](){ nl_socket_free(nl_sk); nl_sk=0; });

  e7_printrc( "genl_connect", rc = genl_connect(nl_sk) );
  assert(rc>-1);

  nl_familyid = genl_ctrl_resolve(nl_sk, ENL_NAME);
  if (nl_familyid<1) { E7_LOG("eftirlit LKM not installed"); return -1; }

  nl_socket_disable_seq_check(nl_sk); // for stateless support
  //nl_socket_disable_auto_ack(nl_sk); // testme: for async support

  int fdnl = nl_socket_get_fd(nl_sk);
  assert(fdnl>0);

  nl_socket_modify_cb(nl_sk, NL_CB_VALID, NL_CB_CUSTOM, e7_nlcallback, NULL);

  // configure epoll

  E7_LOG("configure epoll");

  EPOLL epoll(&sigset);
  epoll.addfd(fdsig);
  epoll.addfd(fdnl);
  epoll.addfd(fdstdin);

  E7_LOG("begin console");

  CMDBUF buf;
  while(!stop)
  {
    int nfds = epoll.pwait();
    assert(nfds>=0);

    for (int n = 0; n < nfds; ++n)
    {
      if (epoll.events[n].data.fd == fdsig)
      {
        stop = true;
      }
      else if (epoll.events[n].data.fd == fdnl)
      {
        e7_printrc( "nl_recvmsgs", nl_recvmsgs_default(nl_sk) ); // 0==EOF +ve==#bytes
      }
      else if (epoll.events[n].data.fd == fdstdin)
      {
        if(0<buf.appendln_noblock(fdstdin)) // 0==incomplete, -ve==error, +ve==complete_length
        {
          e7_parsecmd(buf);
        }
      }
    }
  }

  E7_LOG("Shutting down...");
  e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_MODE, ENL_ATTR_BYE) );

  return 0;
}
