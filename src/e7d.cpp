// eftirlit7 (gpl2) - orthopteroid@gmail.com

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
#include "defs.h"

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

static int e7_compose_send(int comm) {
  MSGSTATE ms;
  if(0>e7_prep(ms, comm)) return -1;
  return e7_send(ms);
}

static int e7_compose_send(int comm, int attr1, uint32_t u32a, int attr2, uint32_t u32b) {
  MSGSTATE ms;
  if(0>e7_prep(ms, comm)) return -1;
  if(0>nla_put_u32(ms.msg, attr1, u32a)) return -1;
  if(0>nla_put_u32(ms.msg, attr2, u32b)) return -1;
  return e7_send(ms);
}

static int e7_compose_send(int comm, int attr, const char* sz) {
  MSGSTATE ms;
  if(0>e7_prep(ms, comm)) return -1;
  if(0>nla_put_string(ms.msg, attr, sz)) return -1;
  return e7_send(ms);
}

static int e7_compose_send(int comm, int attr, uint32_t u32) {
  MSGSTATE ms;
  if(0>e7_prep(ms, comm)) return -1;
  if(0>nla_put_u32(ms.msg, attr, u32)) return -1;
  return e7_send(ms);
}

static int e7_compose_send(int comm, int attr2, uint32_t u32, int attr1, const char* sz) {
  MSGSTATE ms;
  if(0>e7_prep(ms, comm)) return -1;
  if(0>nla_put_u32(ms.msg, attr2, u32)) return -1;
  if(0>nla_put_string(ms.msg, attr1, sz)) return -1;
  return e7_send(ms);
}

//////////////////////

static int e7_nlcallback(struct nl_msg *msg, void *arg) {
  struct nlattr * attribs[ENL_ATTR_MAX +1]; // +1 because attrib 0 is nl_skipped
  struct nlmsghdr * nlh = NULL;
  struct genlmsghdr * gnlh = NULL;
  struct nlattr * gnlad = NULL;
  struct nlattr *a = NULL, *apr = NULL, *apa = NULL;
  uint32_t value = ~0, upr;
  const char * szpath = 0, * szstate = 0, * szprot = 0, * szflag = 0, * szconst = 0;
  int gnlal = 0;

  if(!msg) { E7_LOG("!msg"); return 0; }
  if(!(nlh = nlmsg_hdr(msg))) { E7_LOG("!nlh"); return 0; }
  if(!(gnlh = (struct genlmsghdr *)nlmsg_data(nlh))) { E7_LOG("!gnlh"); return 0; }

  if(gnlh->cmd==ENL_COMM_DISCONNECT) { stop = true; return NL_OK; } // check for fast shutdown

  if(!(gnlad = genlmsg_attrdata(gnlh, 0))) { E7_LOG("!gnlad"); return 0; }
  if(!(gnlal = genlmsg_attrlen(gnlh, 0))) { E7_LOG("empty packet received"); return NL_OK; }

  nla_parse(attribs, ENL_ATTR_MAX, gnlad, gnlal, def_policy);

  switch(gnlh->cmd) {
  case ENL_COMM_ERROR:
    E7_LOG("error returned");
    break;
  case ENL_COMM_DISCONNECT:
    stop = true;
    break;
  case ENL_COMM_GET:
    if((a = attribs[ENL_ATTR_FLAG])) def_flag_name_str(&szflag, nla_get_u32(a));
    if((a = attribs[ENL_ATTR_VALUE])) { value = nla_get_u32(a); def_const_name_str(&szconst, value); }
    E7_LOG("%s = %s (%u)", szflag ? szflag : "(null)", szconst ? szconst : "?", value);
    break;
  case ENL_COMM_EVENT:
    if((a = attribs[ENL_ATTR_STATE])) def_const_name_str(&szstate, nla_get_u32(a));
    if((a = attribs[ENL_ATTR_PROT])) def_protname(&szprot, nla_get_u32(a));
    if((a = attribs[ENL_ATTR_PATH])) szpath = nla_get_string(a);
    E7_LOG("event state %s prot %s path %s", szstate, (szprot ? szprot : "-"), (szpath ? szpath : "-"));
    break;
  case ENL_COMM_QUERY:
    do {
      if((a = attribs[ENL_ATTR_STATE])) def_const_name_str(&szstate, nla_get_u32(a));
      if((apr = attribs[ENL_ATTR_PROT])) { upr = nla_get_u32(apr); def_protname(&szprot, upr); }
      if((apa = attribs[ENL_ATTR_PATH])) szpath = nla_get_string(apa);

      if(!apr && !apa)                E7_LOG("query state %s", szstate);
      else if(!apr && apa && szpath)  E7_LOG("query state %s path %s", szstate, szpath);
      else if(apr && !szprot && !apa) E7_LOG("query state %s prot %d", szstate, upr);
      else if(apr && szprot && !apa)  E7_LOG("query state %s prot %s", szstate, szprot);
      else if(apr && !szprot && apa)  E7_LOG("query state %s prot %d path %s", szstate, upr, szpath);
      else if(apr && szprot && apa)   E7_LOG("query state %s prot %s path %s", szstate, szprot, szpath);

      if(!attribs[ENL_ATTR_NESTED]) break; // end-of-list
      int rc = nla_parse_nested(attribs, ENL_ATTR_MAX, attribs[ENL_ATTR_NESTED], def_policy);
      if(rc!=0) { E7_LOG("!nla_parse_nested"); break; }
    } while(true);
    break;
  default:
    E7_LOG("unrecognized message");
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
  uint32_t iflag, iconst, ivalue;

  // 0==incomplete, -ve==error, +ve==complete_length
  if(0>=buf.appendln_noblock(fdstdin)) return;

  auto is_int_or_const = [](char* sz, uint32_t& u) -> bool
  {
    uint32_t j;
    char *p = sz;
    if(!sz) return false;
    if(def_const_alias_value(&j, sz)) { u = j; return true; }
    while(*p) if(!isdigit(*(p++))) return false;
    u = atoi(sz);
    return true;
  };

  auto is_state = [](char* sz, uint32_t& u) -> bool
  {
    if(!sz) return false;
    if(!def_const_alias_value(&u, sz)) return false;
    return (u == E7C_BLOCK) || (u == E7C_ALLOW);
  };

  auto is_path = [](char* sz) -> bool
  {
    return *sz == '/';
  };

  const char * sz = buf.identifyargs();
  if(sz) E7_LOG("%s", sz);

  int ac = buf.argc;
  char *a0 = buf.arg[0], *a1 = buf.arg[1], *a2 = buf.arg[2];
  switch(crc32(a0))
  {
    case crc32("quit"):
      stop = true;
      break;
    case crc32("bye"):
      e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_DISCONNECT) );
      break;
    case crc32("get"):
      do
      {
        if(ac!=2) break;
        if(!def_flag_alias_idx(&iflag, a1)) break;
        e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_GET, ENL_ATTR_FLAG, iflag) );
        return;
      }
      while (false);
      printf("get <flagname>\n");
      break;
    case crc32("set"):
      do
      {
        if(ac!=3) break;
        if(!def_flag_alias_idx(&iflag, a1)) break;
        if(!is_int_or_const(a2, iconst)) break;
        e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_SET, ENL_ATTR_FLAG, iflag, ENL_ATTR_VALUE, iconst) );
        return;
      }
      while(false);
      printf("set <flagname> ( <constnum> | <constname> )\n");
      break;
    case crc32("block"):
      if(ac==1)                                     e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_BLOCK) );
      else if(ac==2 && is_int_or_const(a1, ivalue)) e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_BLOCK, ENL_ATTR_PROT, ivalue) );
      else if(ac==2 && is_path(a1))                 e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_BLOCK, ENL_ATTR_PATH, a1) );
      else if(ac==3 && is_int_or_const(a1, ivalue) && is_path(a2)) e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_BLOCK, ENL_ATTR_PROT, ivalue, ENL_ATTR_PATH, a2) );
      else printf("allow [ <protocolnum> | <protocolname> ] [ <path/app> | <path/> ]\n");
      break;
    case crc32("allow"):
      if(ac==1)                                     e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_ALLOW) );
      else if(ac==2 && is_int_or_const(a1, ivalue)) e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_ALLOW, ENL_ATTR_PROT, ivalue) );
      else if(ac==2 && is_path(a1))                 e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_ALLOW, ENL_ATTR_PATH, a1) );
      else if(ac==3 && is_int_or_const(a1, ivalue) && is_path(a2)) e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_ALLOW, ENL_ATTR_PROT, ivalue, ENL_ATTR_PATH, a2) );
      else printf("allow [ <protocolnum> | <protocolname> ] [ <path/app> | <path/> ]\n");
      break;
    case crc32("enable"):
      if(ac==1) e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_ENABLE) );
      else printf("enable\n");
      break;
    case crc32("clear"):
      if(ac==1)                                     e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_CLEAR) );
      else if(ac==2 && is_state(a1, ivalue))        e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_CLEAR, ENL_ATTR_STATE, ivalue) );
      else if(ac==2 && is_int_or_const(a1, ivalue)) e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_CLEAR, ENL_ATTR_PROT, ivalue) );
      else if(ac==2 && is_path(a1))                 e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_CLEAR, ENL_ATTR_PATH, a1) );
      else if(ac==3 && is_int_or_const(a1, ivalue) && is_path(a2)) e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_CLEAR, ENL_ATTR_PROT, ivalue, ENL_ATTR_PATH, a2) );
      else printf("clear [ state ] | ( [ <protocolnum> | <protocolname> ] [ <path/app> | <path/> ] )\n");
      break;
    case crc32("query"):
      if(ac==1) e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_QUERY) );
      else printf("query\n");
      break;
    default:
      printf("quit, bye, get, set, block, allow, enable, clear, query\n");
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

  if(0!=(rc = def_init())) { E7_LOG("def_init failed"); return -1; }

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

  e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_QUERY));

  CMDBUF buf;
  while(!stop)
  {
    int nfds = epoll.pwait();
    assert(nfds>=0);

    for (int n = 0; n < nfds; ++n)
    {
      if (epoll.events[n].data.fd == fdsig)
        stop = true;
      else if (epoll.events[n].data.fd == fdnl)
        e7_printrc( "nl_recvmsgs", nl_recvmsgs_default(nl_sk) ); // 0==EOF +ve==#bytes
      else if (epoll.events[n].data.fd == fdstdin)
        e7_parsecmd(buf);
    }
  }

  E7_LOG("Shutting down...");
  e7_printrc( "e7_compose_send", e7_compose_send(ENL_COMM_DISCONNECT));

  return 0;
}
