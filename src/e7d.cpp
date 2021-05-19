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

#define DOUANE_NL_NAME "douane"
#define DOUANE_NL_VERSION 1

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
  DOUANE_NL_COMM_UNSUPP,
  DOUANE_NL_COMM_ECHO, // removeme: old demo code
  DOUANE_NL_COMM_LOG,
  DOUANE_NL_COMM_MODE,
  DOUANE_NL_COMM_RULE,
  DOUANE_NL_COMM_RULES,
  DOUANE_NL_COMM_EVENT,
  __DOUANE_NL_COMM_MAX,
};
#define DOUANE_NL_COMM_MAX (__DOUANE_NL_COMM_MAX-1)

// attribute enumeration
enum {
  DOUANE_NL_ATTR_UNSUPP,
  DOUANE_NL_ATTR_ECHOBODY, // removeme: old demo code
  DOUANE_NL_ATTR_ECHONESTED, // removeme: old demo code
  DOUANE_NL_ATTR_RULENESTED,
  // <state>
  DOUANE_NL_ATTR_ENABLE,
  DOUANE_NL_ATTR_DISABLE,
  // <criteria>
  DOUANE_NL_ATTR_PROCESS_ID,
  DOUANE_NL_ATTR_PROTOCOL_ID,
  DOUANE_NL_ATTR_USER_ID,
  DOUANE_NL_ATTR_GROUP_ID,
  DOUANE_NL_ATTR_PROCESS_STR,
  DOUANE_NL_ATTR_DEVICE_STR,
  // <action>
  DOUANE_NL_ATTR_ALLOW,
  DOUANE_NL_ATTR_BLOCK,
  DOUANE_NL_ATTR_LOG,
  DOUANE_NL_ATTR_NOLOG,
  // misc
  DOUANE_NL_ATTR_REMOVE,
  DOUANE_NL_ATTR_QUERY,
  DOUANE_NL_ATTR_CLEAR,
  DOUANE_NL_ATTR_HELLO,
  DOUANE_NL_ATTR_BYE,
  //
  __DOUANE_NL_ATTR_MAX,
};
#define DOUANE_NL_ATTR_MAX (__DOUANE_NL_ATTR_MAX-1)

///////////

// https://create.stephan-brumme.com/crc32/#sarwate (1988)
static constexpr uint32_t crc32_tab[] = {
    0x00000000,0x77073096,0xee0e612c,0x990951ba,0x076dc419,0x706af48f,0xe963a535,
    0x9e6495a3,0x0edb8832,0x79dcb8a4,0xe0d5e91e,0x97d2d988,0x09b64c2b,0x7eb17cbd,
    0xe7b82d07,0x90bf1d91,0x1db71064,0x6ab020f2,0xf3b97148,0x84be41de,0x1adad47d,
    0x6ddde4eb,0xf4d4b551,0x83d385c7,0x136c9856,0x646ba8c0,0xfd62f97a,0x8a65c9ec,
    0x14015c4f,0x63066cd9,0xfa0f3d63,0x8d080df5,0x3b6e20c8,0x4c69105e,0xd56041e4,
    0xa2677172,0x3c03e4d1,0x4b04d447,0xd20d85fd,0xa50ab56b,0x35b5a8fa,0x42b2986c,
    0xdbbbc9d6,0xacbcf940,0x32d86ce3,0x45df5c75,0xdcd60dcf,0xabd13d59,0x26d930ac,
    0x51de003a,0xc8d75180,0xbfd06116,0x21b4f4b5,0x56b3c423,0xcfba9599,0xb8bda50f,
    0x2802b89e,0x5f058808,0xc60cd9b2,0xb10be924,0x2f6f7c87,0x58684c11,0xc1611dab,
    0xb6662d3d,0x76dc4190,0x01db7106,0x98d220bc,0xefd5102a,0x71b18589,0x06b6b51f,
    0x9fbfe4a5,0xe8b8d433,0x7807c9a2,0x0f00f934,0x9609a88e,0xe10e9818,0x7f6a0dbb,
    0x086d3d2d,0x91646c97,0xe6635c01,0x6b6b51f4,0x1c6c6162,0x856530d8,0xf262004e,
    0x6c0695ed,0x1b01a57b,0x8208f4c1,0xf50fc457,0x65b0d9c6,0x12b7e950,0x8bbeb8ea,
    0xfcb9887c,0x62dd1ddf,0x15da2d49,0x8cd37cf3,0xfbd44c65,0x4db26158,0x3ab551ce,
    0xa3bc0074,0xd4bb30e2,0x4adfa541,0x3dd895d7,0xa4d1c46d,0xd3d6f4fb,0x4369e96a,
    0x346ed9fc,0xad678846,0xda60b8d0,0x44042d73,0x33031de5,0xaa0a4c5f,0xdd0d7cc9,
    0x5005713c,0x270241aa,0xbe0b1010,0xc90c2086,0x5768b525,0x206f85b3,0xb966d409,
    0xce61e49f,0x5edef90e,0x29d9c998,0xb0d09822,0xc7d7a8b4,0x59b33d17,0x2eb40d81,
    0xb7bd5c3b,0xc0ba6cad,0xedb88320,0x9abfb3b6,0x03b6e20c,0x74b1d29a,0xead54739,
    0x9dd277af,0x04db2615,0x73dc1683,0xe3630b12,0x94643b84,0x0d6d6a3e,0x7a6a5aa8,
    0xe40ecf0b,0x9309ff9d,0x0a00ae27,0x7d079eb1,0xf00f9344,0x8708a3d2,0x1e01f268,
    0x6906c2fe,0xf762575d,0x806567cb,0x196c3671,0x6e6b06e7,0xfed41b76,0x89d32be0,
    0x10da7a5a,0x67dd4acc,0xf9b9df6f,0x8ebeeff9,0x17b7be43,0x60b08ed5,0xd6d6a3e8,
    0xa1d1937e,0x38d8c2c4,0x4fdff252,0xd1bb67f1,0xa6bc5767,0x3fb506dd,0x48b2364b,
    0xd80d2bda,0xaf0a1b4c,0x36034af6,0x41047a60,0xdf60efc3,0xa867df55,0x316e8eef,
    0x4669be79,0xcb61b38c,0xbc66831a,0x256fd2a0,0x5268e236,0xcc0c7795,0xbb0b4703,
    0x220216b9,0x5505262f,0xc5ba3bbe,0xb2bd0b28,0x2bb45a92,0x5cb36a04,0xc2d7ffa7,
    0xb5d0cf31,0x2cd99e8b,0x5bdeae1d,0x9b64c2b0,0xec63f226,0x756aa39c,0x026d930a,
    0x9c0906a9,0xeb0e363f,0x72076785,0x05005713,0x95bf4a82,0xe2b87a14,0x7bb12bae,
    0x0cb61b38,0x92d28e9b,0xe5d5be0d,0x7cdcefb7,0x0bdbdf21,0x86d3d2d4,0xf1d4e242,
    0x68ddb3f8,0x1fda836e,0x81be16cd,0xf6b9265b,0x6fb077e1,0x18b74777,0x88085ae6,
    0xff0f6a70,0x66063bca,0x11010b5c,0x8f659eff,0xf862ae69,0x616bffd3,0x166ccf45,
    0xa00ae278,0xd70dd2ee,0x4e048354,0x3903b3c2,0xa7672661,0xd06016f7,0x4969474d,
    0x3e6e77db,0xaed16a4a,0xd9d65adc,0x40df0b66,0x37d83bf0,0xa9bcae53,0xdebb9ec5,
    0x47b2cf7f,0x30b5ffe9,0xbdbdf21c,0xcabac28a,0x53b39330,0x24b4a3a6,0xbad03605,
    0xcdd70693,0x54de5729,0x23d967bf,0xb3667a2e,0xc4614ab8,0x5d681b02,0x2a6f2b94,
    0xb40bbe37,0xc30c8ea1,0x5a05df1b,0x2d02ef8d
};

constexpr uint32_t crc32(uint32_t previouscrc, const char* s, int len)
{
  uint32_t crc = ~previouscrc;
  for(int i = 0;  i < len;  i++) {
      crc = (crc >> 8) ^ crc32_tab[ (crc & (uint32_t)0xFF) ^ s[i] ];
  }
  return ~crc;
}

constexpr uint32_t crc32(const char* sz)
{
  uint32_t crc = ~0;
  for(int i = 0;  sz[i] != 0;  i++) {
      crc = (crc >> 8) ^ crc32_tab[ (crc & (uint32_t)0xFF) ^ sz[i] ];
  }
  return ~crc;
}

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

static int e7_prep(MSGSTATE* ms, uint8_t comm) {
  ms->msg = nlmsg_alloc();
  if (ms->msg<0) return -1;

  ms->hdr = genlmsg_put(ms->msg, NL_AUTO_PORT, NL_AUTO_SEQ, nl_familyid, 0, 0, comm, DOUANE_NL_VERSION);
  if (ms->hdr) return 0;

  if (ms->msg) nlmsg_free(ms->msg);
  ms->msg = 0;
  return -1;
}

static int e7_send(MSGSTATE* ms) {
  if (!ms->msg || !ms->hdr) return -1;

  int rc = nl_send_auto(nl_sk, ms->msg); // review: "unknown or invalid cache type" error

  if (0>rc && ms->msg) nlmsg_free(ms->msg);
  ms->msg = 0;
  ms->hdr = 0;
  return rc;
}

static int e7_nlcallback(struct nl_msg *msg, void *arg) {
  struct nlattr * attribs[DOUANE_NL_ATTR_MAX +1]; // +1 because attrib 0 is nl_skipped

  struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
  nla_parse(attribs, DOUANE_NL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

  switch(gnlh->cmd) {
  case DOUANE_NL_COMM_ECHO:
    printf("Kernel replied: %s\n", nla_get_string(attribs[DOUANE_NL_ATTR_ECHOBODY]));
    break;
  case DOUANE_NL_COMM_LOG:
    printf("Unrecognized log message\n");
    break;
  case DOUANE_NL_COMM_MODE:
    printf("DOUANE_NL_COMM_MODE message\n");
    if(attribs[DOUANE_NL_ATTR_BYE]) stop = true;
    break;
  case DOUANE_NL_COMM_RULE:
    printf("Unrecognized rule message\n");
    break;
  case DOUANE_NL_COMM_RULES:
    printf("Unrecognized rules message\n");
/* TODO: parse nested rules
  if(info->attrs[DOUANE_NL_ATTR_ECHONESTED])
  {
    struct nlattr * curr_attrs[DOUANE_NL_ATTR_MAX +1]; // +1 because attrib 0 is nl_skipped

    memcpy(curr_attrs, info->attrs, sizeof(curr_attrs));

    LOG_DEBUG(stack_id, "received list");

    do {
      int rc = 0;

      tmp_attr = curr_attrs[DOUANE_NL_ATTR_ECHONESTED];
      if(!tmp_attr) { LOG_DEBUG(stack_id, "end of list"); break; }

      memset(curr_attrs, 0, sizeof(curr_attrs));
      rc = nla_parse_nested(curr_attrs, DOUANE_NL_ATTR_MAX, tmp_attr, e7_policy, NULL);
      if(rc!=0) { LOG_ERR(stack_id, "!nla_parse_nested"); break; }

      tmp_attr = curr_attrs[DOUANE_NL_ATTR_ECHOBODY];
      if(!tmp_attr) { LOG_ERR(stack_id, "!DOUANE_NL_ATTR_ECHOBODY"); break; }

      mydata = (char*)nla_data(tmp_attr);
      if(!mydata) { LOG_ERR(stack_id, "!nla_data"); break; }

      if(!nl_rfns) goto fail;
      nl_rfns->recv_echo(mydata, stack_id);
    } while(true);
  }
*/
    break;
  case DOUANE_NL_COMM_EVENT:
    printf("event %s\n", nla_get_string(attribs[DOUANE_NL_ATTR_PROCESS_STR]));
    break;
  default:
    printf("Unrecognized message\n");
    break;
  }

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

  printf("configure sighandler\n");

  sigset_t sigset;
  rc = sigemptyset(&sigset) | sigaddset(&sigset, SIGINT) | sigprocmask(SIG_BLOCK, &sigset, NULL);
  assert(!rc);

  int fdsig = signalfd(-1, &sigset, 0);
  assert(0<fdsig);
  auto close_fdsig = defer([&](){ close(fdsig); fdsig=0; });

  printf("configure netlink\n");

  nl_sk = nl_socket_alloc();
  assert(nl_sk);
  auto close_nlsk = defer([&](){ nl_socket_free(nl_sk); nl_sk=0; });

  e7_printrc( "genl_connect", rc = genl_connect(nl_sk) );
  assert(rc>-1);

  nl_familyid = genl_ctrl_resolve(nl_sk, "douane");
  if (nl_familyid<1) {
    printf("douane module not installed\n");
    return -1;
  }

  nl_socket_disable_seq_check(nl_sk); // for stateless support
  //nl_socket_disable_auto_ack(nl_sk); // testme: for async support

  int fdnl = nl_socket_get_fd(nl_sk);
  assert(fdnl>0);

  nl_socket_modify_cb(nl_sk, NL_CB_VALID, NL_CB_CUSTOM, e7_nlcallback, NULL);

  // configure epoll

  printf("configure epoll\n");

  EPOLL epoll(&sigset);
  epoll.addfd(fdsig);
  epoll.addfd(fdnl);
  epoll.addfd(fdstdin);

  printf("begin console\n");

  while(!stop) {
    MSGSTATE ms;
    CMDBUF buf;

    int nfds = epoll.pwait();
    assert(nfds>=0);

    for (int n = 0; n < nfds; ++n) {
      if (epoll.events[n].data.fd == fdsig) {
        stop = true;
      } else if (epoll.events[n].data.fd == fdnl) {
        e7_printrc( "nl_recvmsgs", nl_recvmsgs_default(nl_sk) ); // 0==EOF +ve==#bytes
      } else if (epoll.events[n].data.fd == fdstdin) {
        if(0<buf.appendln_noblock(fdstdin)) // 0==incomplete, -ve==error, +ve==complete_length
        {
          switch(crc32(buf.text))
          {
            case crc32("help"):
              printf("ya whatever\n");
              break;
            case crc32("hello"):
              e7_printrc( "e7_prep", e7_prep(&ms, DOUANE_NL_COMM_MODE) );
              e7_printrc( "nla_put_flag", nla_put_flag(ms.msg, DOUANE_NL_ATTR_HELLO) );
              e7_printrc( "e7_send", e7_send(&ms) );
              break;
            case crc32("bye"):
              e7_printrc( "e7_prep", e7_prep(&ms, DOUANE_NL_COMM_MODE) );
              e7_printrc( "nla_put_flag", nla_put_flag(ms.msg, DOUANE_NL_ATTR_BYE) );
              e7_printrc( "e7_send", e7_send(&ms) );
              //stop = true;
              break;
            case crc32("hiby"):
              e7_printrc( "e7_prep", e7_prep(&ms, DOUANE_NL_COMM_MODE) );
              e7_printrc( "nla_put_flag", nla_put_flag(ms.msg, DOUANE_NL_ATTR_HELLO) );
              e7_printrc( "nla_put_flag", nla_put_flag(ms.msg, DOUANE_NL_ATTR_BYE) );
              e7_printrc( "e7_send", e7_send(&ms) );
              //stop = true;
              break;
            case crc32("echo"):
              e7_printrc( "e7_prep", e7_prep(&ms, DOUANE_NL_COMM_ECHO) );
              e7_printrc( "nla_put_string", nla_put_string(ms.msg, DOUANE_NL_ATTR_ECHOBODY, "Hello World") );
              e7_printrc( "e7_send", e7_send(&ms) );
              break;
            case crc32("en"): // echonest
              {
                e7_printrc( "e7_prep", e7_prep(&ms, DOUANE_NL_COMM_ECHO) );
                e7_printrc( "nla_put_string", nla_put_string(ms.msg, DOUANE_NL_ATTR_ECHOBODY, "OUTER") );
                // a list built with recursive enumeration...
                std::deque<struct nlattr *> attrptr_stack;
                std::string inner;
                for(int z=0;z<3;z++)
                {
                  // there appears to be overhead for each entry, but it seems to be around DOUANE_NL_ATTR_MAX bytes. hmmm.
                  inner = inner + "INNER ";
                  attrptr_stack.push_front( nla_nest_start(ms.msg, DOUANE_NL_ATTR_ECHONESTED | NLA_F_NESTED) ); // | NESTED required with ubuntu libnl 3.2.29
                  e7_printrc( "nla_put_string", nla_put_string(ms.msg, DOUANE_NL_ATTR_ECHOBODY, inner.c_str()) );
                }
                while(!attrptr_stack.empty())
                {
                  nla_nest_end(ms.msg, attrptr_stack.front());
                  attrptr_stack.pop_front();
                }
                e7_printrc( "e7_send", e7_send(&ms) );
              }
              break;
            default:
              printf("huh?\n");
          }
        }
      }
    }
  }

  printf("Shutting down...\n");
  e7_printrc( "e7_prep", e7_prep(&ms, DOUANE_NL_COMM_MODE) );
  e7_printrc( "nla_put_flag", nla_put_flag(ms.msg, DOUANE_NL_ATTR_BYE) );
  e7_printrc( "e7_send", e7_send(&ms) );

  return 0;
}
