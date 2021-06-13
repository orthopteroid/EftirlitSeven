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

#define ENL_NAME "eftirlit"
#define ENL_VERSION 1

// <state> = enable | disable
// <criteria> = [process] [protocol] [device] [user] [group]
// <action> = (allow | block) [log | nolog]
// LOG u->m = <state> | query
// LOG u<-m = <state>
// MODE u->m = <state> | query | hello | bye
// MODE u<-m = <state> | bye
// RULE u->m = <criteria> <action> [<state> | remove]
// RULES u->m = query | clear
// RULES u<-m = <criteria> <action> <state>
// EVENT u<-m = <criteria>

// command enumeration
enum {
  ENL_COMM_UNSUPP,
  ENL_COMM_ECHO, // removeme: old demo code
  ENL_COMM_LOG,
  ENL_COMM_MODE,
  ENL_COMM_RULE,
  ENL_COMM_RULES,
  ENL_COMM_EVENT,
  __ENL_COMM_MAX,
};
#define ENL_COMM_MAX (__ENL_COMM_MAX-1)

// attribute enumeration
enum {
  ENL_ATTR_UNSUPP,
  ENL_ATTR_ECHOBODY, // removeme: old demo code
  ENL_ATTR_ECHONESTED, // removeme: old demo code
  ENL_ATTR_RULENESTED,
  // <state>
  ENL_ATTR_ENABLE,
  ENL_ATTR_DISABLE,
  ENL_ATTR_AUTO,
  ENL_ATTR_MANUAL,
  // <criteria>
  ENL_ATTR_CONTEXT_ID,
  ENL_ATTR_PROCESS_ID,
  ENL_ATTR_PROTOCOL_ID,
  ENL_ATTR_USER_ID,
  ENL_ATTR_GROUP_ID,
  ENL_ATTR_PROCESS_STR,
  ENL_ATTR_DEVICE_STR,
  // <action>
  ENL_ATTR_ALLOW,
  ENL_ATTR_BLOCK,
  ENL_ATTR_LOG,
  ENL_ATTR_NOLOG,
  // misc
  ENL_ATTR_REMOVE,
  ENL_ATTR_QUERY,
  ENL_ATTR_CLEAR,
  ENL_ATTR_HELLO,
  ENL_ATTR_BYE,
  //
  __ENL_ATTR_MAX,
};
#define ENL_ATTR_MAX (__ENL_ATTR_MAX-1)

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
  else if (rc>0)
    printf("%s: %d bytes sent\n",cxt,rc);
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
  uint32_t u32 = 0;
  char * sz = 0;
  int gnlal = 0;

  //E7_LOG("start");

  if(!msg) { E7_LOG("!msg"); return 0; }
  if(!(nlh = nlmsg_hdr(msg))) { E7_LOG("!nlh"); return 0; }
  if(!(gnlh = (struct genlmsghdr *)nlmsg_data(nlh))) { E7_LOG("!gnlh"); return 0; }
  if(!(gnlad = genlmsg_attrdata(gnlh, 0))) { E7_LOG("!gnlad"); return 0; }
  if(!(gnlal = genlmsg_attrlen(gnlh, 0))) { E7_LOG("!gnlal"); return 0; }
  nla_parse(attribs, ENL_ATTR_MAX, gnlad, gnlal, NULL);

  switch(gnlh->cmd) {
  case ENL_COMM_ECHO:
    do {
      if(!(a = attribs[ENL_ATTR_ECHOBODY])) { E7_LOG("!a"); break; }
      if(!(sz = nla_get_string(a))) { E7_LOG("!sz"); break; }
      E7_LOG("Kernel replied: %s", sz);
    } while(false);
    break;
  case ENL_COMM_LOG:
    E7_LOG("Unrecognized log message");
    break;
  case ENL_COMM_MODE:
    E7_LOG("ENL_COMM_MODE message");
    if(attribs[ENL_ATTR_BYE]) stop = true;
    break;
  case ENL_COMM_RULE:
    E7_LOG("Unrecognized rule message");
    break;
  case ENL_COMM_RULES:
    E7_LOG("Unrecognized rules message");
/* TODO: parse nested rules
  if(info->attrs[ENL_ATTR_ECHONESTED])
  {
    struct nlattr * curr_attrs[ENL_ATTR_MAX +1]; // +1 because attrib 0 is nl_skipped

    memcpy(curr_attrs, info->attrs, sizeof(curr_attrs));

    LOG_DEBUG(stack_id, "received list");

    do {
      int rc = 0;

      tmp_attr = curr_attrs[ENL_ATTR_ECHONESTED];
      if(!tmp_attr) { LOG_DEBUG(stack_id, "end of list"); break; }

      memset(curr_attrs, 0, sizeof(curr_attrs));
      rc = nla_parse_nested(curr_attrs, ENL_ATTR_MAX, tmp_attr, e7_policy, NULL);
      if(rc!=0) { LOG_ERR(stack_id, "!nla_parse_nested"); break; }

      tmp_attr = curr_attrs[ENL_ATTR_ECHOBODY];
      if(!tmp_attr) { LOG_ERR(stack_id, "!ENL_ATTR_ECHOBODY"); break; }

      mydata = (char*)nla_data(tmp_attr);
      if(!mydata) { LOG_ERR(stack_id, "!nla_data"); break; }

      if(!nl_rfns) goto fail;
      nl_rfns->recv_echo(mydata, stack_id);
    } while(true);
  }
*/
    break;
  case ENL_COMM_EVENT:
    do {
      if(!(a = attribs[ENL_ATTR_PROCESS_STR])) { E7_LOG("!a"); break; }
      if(!(sz = nla_get_string(a))) { E7_LOG("!sz"); break; }
      if((a = attribs[ENL_ATTR_QUERY]))
      {
        u32 = nla_get_u32(a);
        E7_LOG("event %s query %d", sz, u32);
      }
      else
      {
        E7_LOG("event %s", sz);
      }
    } while(false);
    break;
  default:
    E7_LOG("Unrecognized message");
    break;
  }

  //E7_LOG("done");

  return NL_OK;
}

///////////////////

const int fdstdin = 0;

struct CMDBUF
{
  const static int len = 100;

  char text[len];
  int idx = 0;

  // return +ve length of \n terminated string
  // return -1 on error or untermed string
  int appendln_noblock(int fd)
  {
    while(idx<len)
    {
      int rc = read(fd, (void*)&text[idx], 1); // read single char
      if (0==rc) return -EAGAIN; // no data
      if (0>rc) return rc; // other err
      if ('\n'==text[idx])
      {
        text[idx] = '\0';
        int cl = idx;
        idx = 0; // reset to buf start for next line
        return cl;
      }
      idx++;
    }
    return -EFAULT; // buffer overflow
  }
};

/////////////////

void e7_parsecmd(CMDBUF & buf)
{
  MSGSTATE ms;
  switch(crc32(buf.text))
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
      printf("quit, hi, by, hibye, echo, echolist\n");
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

  nl_familyid = genl_ctrl_resolve(nl_sk, "eftirlit");
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
