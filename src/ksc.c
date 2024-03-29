// eftirlit7 (gpl2) - orthopteroid@gmail.com
// forked from douane-lkms (gpl2) - zedtux@zedroot.org

#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/version.h>        // Needed for LINUX_VERSION_CODE >= KERNEL_VERSION

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
#include "fnv1a32.h"
#include "ksc.h"

// douane: the concept of a cache of known sockets were kept in an rcu_list
// of psi_struct. In e7 the concept was kept but changed to a struct-of-array
// style cache for better searching performance.

#define DEBUG_KSC_ASYNC

#ifdef DEBUG_KSC_ASYNC
#define LOG_DEBUG_ASYNC LOG_DEBUG
#else // DEBUG_KSC_ASYNC
#define LOG_DEBUG_ASYNC(fmt, ...) do {} while(false)
#endif // DEBUG_KSC_ASYNC

#define ALIGNED ____cacheline_aligned

#define CACHE_KEY_MASK 0b11111111
#define KEY_CUTTER(v) ((v * 65437) + (v >> 6) + (v >> 13)) // 2^16-99, per https://primes.utm.edu/lists/2small/0bit.html

#define CACHE_FACTOR 2
#define CACHE_SLOTS (CACHE_FACTOR * (CACHE_KEY_MASK +1))
#define KEY_TO_SLOT(v) (CACHE_FACTOR * (KEY_CUTTER(v) & CACHE_KEY_MASK))

typedef char process_path_t[PATH_LENGTH +1];

// struct-of-array layout for better cpu performance
struct ksc_data
{
  unsigned long  i_ino[CACHE_SLOTS] ALIGNED;
  pid_t          pid[CACHE_SLOTS] ALIGNED;
  uint32_t       sequence[CACHE_SLOTS] ALIGNED;
  process_path_t path[CACHE_SLOTS] ALIGNED; // review: ALIGN vs sizeof issues?
  uint32_t       path_hash[CACHE_SLOTS] ALIGNED;

  // bookkeeping baloney
  uint8_t        age[CACHE_SLOTS] ALIGNED;
  uint8_t        inuse[CACHE_SLOTS] ALIGNED;
  uint16_t       key_ino[CACHE_SLOTS] ALIGNED;
  uint16_t       key_seq[CACHE_SLOTS] ALIGNED;
  uint8_t        era ALIGNED;
};

struct ksc_data * ksc_data = 0;

///////////

struct change_work
{
  unsigned long   i_ino;
  pid_t           pid;
  uint32_t        sequence;
  process_path_t  path;
  uint32_t        path_hash;
  uint32_t        packet_id;
  uint8_t         age;
  //
  struct work_struct worker;
  struct rcu_head rcu;
};

////////////

static void ksc_async_remember(struct rcu_head *work)
{
  struct change_work * change = container_of(work, struct change_work, rcu);
  int rnd = change->packet_id % CACHE_SLOTS;
  uint8_t era = ksc_data->era;
  uint16_t era0, era1;
  uint8_t oldest_age;
  int oldest_index;
  int i, k;

  if (!ksc_data)
  {
    LOG_ERR(change->packet_id, "!ksc_data");
    goto ack;
  }

  era0 = (uint16_t)era;
  era1 = 0xFF + (uint16_t)era;;
  oldest_age = 0;
  oldest_index = rnd;

  //for(i=0, k=0; i<CACHE_SLOTS; i++, k++)  // sequential allocation useful for debugging
  for(i=0, k=rnd; i<CACHE_SLOTS; i++, k++) // makes holes in cache to reduce searchtime for free slot
  {
    if (k == CACHE_SLOTS) k = 0;
    {
      uint16_t era2 = (ksc_data->age[k] <= era0) ? era0 : era1;
      if (oldest_age < (era2 - ksc_data->age[k]))
      {
        oldest_age = (era2 - (uint16_t)ksc_data->age[k]);
        oldest_index = k;
      }
    }
    if (ksc_data->inuse[k]) continue;

    LOG_DEBUG(change->packet_id, "free cache slot selected");
    goto out;
  }

  k = oldest_index;
  LOG_DEBUG(change->packet_id, "cache full. oldest slot selected");

out:
  LOG_DEBUG(change->packet_id, "writing to slot %d", k);

  ksc_data->i_ino[k] = change->i_ino;
  ksc_data->pid[k] = change->pid;
  ksc_data->sequence[k] = change->sequence;
  strncpy(ksc_data->path[k], change->path, PATH_LENGTH);
  ksc_data->path_hash[k] = e7_fnv1a32(change->path);

  // tracking/indicies
  ksc_data->age[k] = change->age;
  ksc_data->inuse[k] = true;
  ksc_data->key_ino[ KEY_TO_SLOT(change->i_ino) ] = k;
  ksc_data->key_seq[ KEY_TO_SLOT(change->sequence) ] = k;

  ksc_data->era++;

ack:
  kfree(change);

  LOG_DEBUG_ASYNC(change->packet_id, "async work complete");
}

static void ksc_async_forget(struct rcu_head *work)
{
  struct change_work * change = container_of(work, struct change_work, rcu);
  int i, k;

  if (!ksc_data)
  {
    LOG_ERR(change->packet_id, "!ksc_data");
    goto ack;
  }

  for(i=0, k = ksc_data->key_ino[ KEY_TO_SLOT(change->i_ino) ]; i<CACHE_SLOTS; ++i, ++k)
  {
    if (k == CACHE_SLOTS) k = 0;
    if (ksc_data->i_ino[k] != change->i_ino) continue;
    if (!ksc_data->inuse[k]) continue;

    ksc_data->inuse[k] = false;
    break;
  }

ack:
  kfree(change);

  LOG_DEBUG_ASYNC(change->packet_id, "async work complete");
}

static void ksc_async_update_all(struct rcu_head *work)
{
  struct change_work * change = container_of(work, struct change_work, rcu);
  int i, k;

  if (!ksc_data)
  {
    LOG_ERR(change->packet_id, "!ksc_data");
    goto ack;
  }

  for(i=0, k = ksc_data->key_ino[ KEY_TO_SLOT(change->i_ino) ]; i<CACHE_SLOTS; ++i, ++k)
  {
    if (k == CACHE_SLOTS) k = 0;
    if (ksc_data->i_ino[k] != change->i_ino) continue;
    if (!ksc_data->inuse[k]) continue;

    ksc_data->i_ino[k] = change->i_ino;
    ksc_data->pid[k] = change->pid;
    ksc_data->sequence[k] = change->sequence;
    strncpy(ksc_data->path[k], change->path, PATH_LENGTH);
    ksc_data->path_hash[k] = e7_fnv1a32(change->path);

    // tracking/indicies
    ksc_data->age[k] = change->age;
    ksc_data->inuse[k] = true;
    ksc_data->key_ino[ KEY_TO_SLOT(change->i_ino) ] = k;
    ksc_data->key_seq[ KEY_TO_SLOT(change->sequence) ] = k;
    break;
  }

ack:
  kfree(change);

  LOG_DEBUG_ASYNC(change->packet_id, "async work complete");
}

static void ksc_async_update_seq(struct rcu_head *work)
{
  struct change_work * change = container_of(work, struct change_work, rcu);
  int i, k;

  if (!ksc_data)
  {
    LOG_ERR(change->packet_id, "!ksc_data");
    goto ack;
  }

  for(i=0, k = ksc_data->key_ino[ KEY_TO_SLOT(change->i_ino) ]; i<CACHE_SLOTS; ++i, ++k)
  {
    if (k == CACHE_SLOTS) k = 0;
    if (ksc_data->i_ino[k] != change->i_ino) continue;
    if (!ksc_data->inuse[k]) continue;
    if (ksc_data->sequence[k] == change->sequence) break; // no change needed

    ksc_data->sequence[k] = change->sequence;
    ksc_data->age[k] = change->age;
    break;
  }
  
ack:
  kfree(change);

  LOG_DEBUG_ASYNC(change->packet_id, "async work complete");
}

static void ksc_async_update_age(struct rcu_head *work)
{
  struct change_work * change = container_of(work, struct change_work, rcu);
  int i, k;

  if (!ksc_data)
  {
    LOG_ERR(change->packet_id, "!ksc_data");
    goto ack;
  }

  for(i=0, k = ksc_data->key_ino[ KEY_TO_SLOT(change->i_ino) ]; i<CACHE_SLOTS; ++i, ++k)
  {
    if (k == CACHE_SLOTS) k = 0;
    if (ksc_data->i_ino[k] != change->i_ino) continue;
    if (!ksc_data->inuse[k]) continue;

    ksc_data->age[k] = change->age;
    break;
  }
  
ack:
  kfree(change);

  LOG_DEBUG_ASYNC(change->packet_id, "async work complete");
}

static void ksc_async_clearcache(struct rcu_head *work)
{
  struct change_work * change = container_of(work, struct change_work, rcu);

  memset(ksc_data, 0, sizeof(struct ksc_data));
  
  kfree(change);

  LOG_DEBUG_ASYNC(change->packet_id, "async work complete");
}

////////////////////////

bool ksc_from_inode(struct psi * psi_out, const unsigned long i_ino, const uint32_t packet_id)
{
  int i, k;

  if (!ksc_data)
  {
    LOG_ERR(packet_id, "!ksc_data");
    return false;
  }

  // log-squash
  //LOG_DEBUG(packet_id, "searching for INO %lu", i_ino);

  rcu_read_lock();
  for(i=0, k = ksc_data->key_ino[ KEY_TO_SLOT(i_ino) ]; i<CACHE_SLOTS; ++i, ++k)
  {
    if (k == CACHE_SLOTS) k = 0;
    if (ksc_data->i_ino[k] != i_ino) continue;
    if (!ksc_data->inuse[k]) continue;

    psi_out->i_ino = ksc_data->i_ino[k];
    psi_out->pid = ksc_data->pid[k];
    psi_out->sequence = ksc_data->sequence[k];
    strncpy(psi_out->process_path, ksc_data->path[k], PATH_LENGTH);
    rcu_read_unlock();
  
    LOG_DEBUG(packet_id, "found INO %lu in slot %d", i_ino, k);
    return true;
  }
  rcu_read_unlock();
  
  LOG_DEBUG(packet_id, "searching for INO %lu - not found", i_ino);
  return false;
}

bool ksc_from_sequence(struct psi * psi_out, const uint32_t sequence, const uint32_t packet_id)
{
  int i, k;

  if (!ksc_data)
  {
    LOG_ERR(packet_id, "!ksc_data");
    return false;
  }

  // log-squash
  //LOG_DEBUG(packet_id, "searching for SEQ %u", sequence);

  rcu_read_lock();
  for(i=0, k = ksc_data->key_seq[ KEY_TO_SLOT(sequence) ]; i<CACHE_SLOTS; ++i, ++k)
  {
    if (k == CACHE_SLOTS) k = 0;
    if (!ksc_data->sequence[k]) continue;
    if ((ksc_data->sequence[k] != sequence) && ((ksc_data->sequence[k] + 1) != sequence)) continue;
    if (!ksc_data->inuse[k]) continue;

    psi_out->i_ino = ksc_data->i_ino[k];
    psi_out->pid = ksc_data->pid[k];
    psi_out->sequence = ksc_data->sequence[k];
    strncpy(psi_out->process_path, ksc_data->path[k], PATH_LENGTH);
    rcu_read_unlock();

    LOG_DEBUG(packet_id, "found SEQ %u in slot %d", sequence, k);
    return true;
  }
  rcu_read_unlock();
  
  LOG_DEBUG(packet_id, "searching for SEQ %u - not found", sequence);
  return false;
}

void ksc_forget(const unsigned long i_ino, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }

  LOG_DEBUG_ASYNC(packet_id, "queuing async call to forget entry for INO %lu", i_ino);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  //
  call_rcu(&new_work->rcu, ksc_async_forget);
}

void ksc_clear(const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  LOG_DEBUG(packet_id, "cleaning");

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }

  new_work->packet_id = packet_id;
  //
  call_rcu(&new_work->rcu, ksc_async_clearcache);
}

void ksc_remember(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }

  LOG_DEBUG_ASYNC(packet_id, "queueing async call to remember entry INO %lu PID %d SEQ %u PATH %s", i_ino, pid, sequence, path);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  new_work->pid = pid;
  new_work->sequence = sequence;
  strncpy(new_work->path, path, PATH_LENGTH);
  new_work->path_hash = e7_fnv1a32(path);
  new_work->age = ksc_data->era;
  //
  call_rcu(&new_work->rcu, ksc_async_remember);
}

void ksc_update_all(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }

  LOG_DEBUG_ASYNC(packet_id, "queueing async call to update_all for INO %lu", i_ino);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  new_work->pid = pid;
  new_work->sequence = sequence;
  strncpy(new_work->path, path, PATH_LENGTH);
  new_work->path_hash = e7_fnv1a32(path);
  new_work->age = ksc_data->era;
  //
  call_rcu(&new_work->rcu, ksc_async_update_all);
}

void ksc_update_seq(const unsigned long i_ino, const uint32_t sequence, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }

  LOG_DEBUG_ASYNC(packet_id, "queueing async call to update_seq for INO %lu", i_ino);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  new_work->sequence = sequence;
  new_work->age = ksc_data->era;
  //
  call_rcu(&new_work->rcu, ksc_async_update_seq);
}

void ksc_update_age(const unsigned long i_ino, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }

  LOG_DEBUG_ASYNC(packet_id, "queueing async call to update_age INO %lu", i_ino);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  new_work->age = ksc_data->era;
  //
  call_rcu(&new_work->rcu, ksc_async_update_age);
}

int ksc_init(void)
{
  LOG_INFO(0, "cache %u entries %lu kb", CACHE_SLOTS, sizeof(struct ksc_data) / 1024);
  ksc_data = kzalloc(sizeof(struct ksc_data), GFP_ATOMIC); // fixme
  if (!ksc_data)
  {
    LOG_ERR(0, "kzalloc failed");
    return -1;
  }

  return 0;
}

void ksc_exit(void)
{
  kfree(ksc_data); // review: rcu?
}
