// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/version.h>        // Needed for LINUX_VERSION_CODE >= KERNEL_VERSION

#include <linux/netdevice.h>	    // net_device
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

#include "douane_types.h"
#include "psi.h"
#include "module.h"

#define ALIGNED __attribute__ ((aligned (__BIGGEST_ALIGNMENT__)));

// cache size is paired with the key cutter size
#define CACHE_SIZE 128
#define KEY_CUTTER(v) (v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24))

typedef char process_path_t[PATH_LENGTH +1];

// struct-of-array layout for better cpu performance
struct data_cache
{
  unsigned long  i_ino[CACHE_SIZE] ALIGNED;
  pid_t          pid[CACHE_SIZE] ALIGNED;
  uint32_t       sequence[CACHE_SIZE] ALIGNED;
  process_path_t path[CACHE_SIZE] ALIGNED;
  uint32_t       path_hash[CACHE_SIZE] ALIGNED;

  // bookkeeping baloney
  uint8_t        age[CACHE_SIZE] ALIGNED;
  uint8_t        inuse[CACHE_SIZE] ALIGNED;
  uint8_t        key_ino[CACHE_SIZE] ALIGNED;
  uint8_t        key_seq[CACHE_SIZE] ALIGNED;
  uint8_t        era ALIGNED;
};

struct data_cache * psi_cache_data = 0;

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

DEFINE_SPINLOCK(psi_workq_lock);
struct workqueue_struct * psi_change_workq;

////////////

// https://create.stephan-brumme.com/crc32/#sarwate (1988)
static uint32_t crc32_tab[] = {
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

static uint32_t crc32(const char* sz)
{
  uint32_t crc = ~0, i;
  for(i = 0;  sz[i] != 0;  i++) {
      crc = (crc >> 8) ^ crc32_tab[ (crc & (uint32_t)0xFF) ^ sz[i] ];
  }
  return ~crc;
}

////////////

static void psi_async_remember(struct work_struct *work)
{
	struct change_work * change = container_of(work, struct change_work, worker);
  int rnd = change->packet_id & (CACHE_SIZE -1);
  uint8_t era = psi_cache_data->era;
  uint16_t era0, era1;
  uint8_t oldest_age;
  int oldest_index;
  int i, k;

  era0 = (uint16_t)era;
  era1 = 0xFF + (uint16_t)era;;
  oldest_age = 0;
  oldest_index = rnd;

  //for(i=0, k=0; i<CACHE_SIZE; i++, k++)  // sequential allocation useful for debugging
  for(i=0, k=rnd; i<CACHE_SIZE; i++, k++) // makes holes in cache to reduce searchtime for free slot
  {
    if (k == CACHE_SIZE) k = 0;
    {
      uint16_t era2 = (psi_cache_data->age[k] <= era0) ? era0 : era1;
      if (oldest_age < (era2 - psi_cache_data->age[k]))
      {
        oldest_age = (era2 - (uint16_t)psi_cache_data->age[k]);
        oldest_index = k;
      }
    }
    if (psi_cache_data->inuse[k]) continue;

    LOG_DEBUG(change->packet_id, "free cache slot selected");
    goto out;
  }

  k = oldest_index;
  LOG_DEBUG(change->packet_id, "cache full. oldest slot selected");

out:
  LOG_DEBUG(change->packet_id, "writing to slot %d", k);

  psi_cache_data->i_ino[k] = change->i_ino;
  psi_cache_data->pid[k] = change->pid;
  psi_cache_data->sequence[k] = change->sequence;
  strncpy(psi_cache_data->path[k], change->path, PATH_LENGTH);
  psi_cache_data->path_hash[k] = crc32(change->path);

  // tracking/indicies
  psi_cache_data->age[k] = change->age;
  psi_cache_data->inuse[k] = true;
  psi_cache_data->key_ino[ KEY_CUTTER(change->i_ino) & (CACHE_SIZE -1) ] = k;
  psi_cache_data->key_seq[ KEY_CUTTER(change->sequence) & (CACHE_SIZE -1) ] = k;

  psi_cache_data->era++;

  kfree_rcu(change, rcu);

  LOG_DEBUG(change->packet_id, "async work complete");
}

static void psi_async_forget(struct work_struct *work)
{
	struct change_work * change = container_of(work, struct change_work, worker);
  int i, k;

  for(i=0, k = psi_cache_data->key_ino[ KEY_CUTTER(change->i_ino) & (CACHE_SIZE -1) ]; i<CACHE_SIZE; i++, k++)
  {
    if (psi_cache_data->i_ino[k] != change->i_ino) continue;
    if (!psi_cache_data->inuse[k]) continue;

    psi_cache_data->inuse[k] = false;
    break;
  }

  kfree_rcu(change, rcu);

  LOG_DEBUG(change->packet_id, "async work complete");
}

static void psi_async_update_all(struct work_struct *work)
{
	struct change_work * change = container_of(work, struct change_work, worker);
  int i, k;

  for(i=0, k = psi_cache_data->key_ino[ KEY_CUTTER(change->i_ino) & (CACHE_SIZE -1) ]; i<CACHE_SIZE; i++, k++)
  {
    if (k == CACHE_SIZE) k = 0;
    if (psi_cache_data->i_ino[k] != change->i_ino) continue;
    if (!psi_cache_data->inuse[k]) continue;

    psi_cache_data->i_ino[k] = change->i_ino;
    psi_cache_data->pid[k] = change->pid;
    psi_cache_data->sequence[k] = change->sequence;
    strncpy(psi_cache_data->path[k], change->path, PATH_LENGTH);
    psi_cache_data->path_hash[k] = crc32(change->path);

    // tracking/indicies
    psi_cache_data->age[k] = change->age;
    psi_cache_data->inuse[k] = true;
    psi_cache_data->key_ino[ KEY_CUTTER(change->i_ino) & (CACHE_SIZE -1) ] = k;
    psi_cache_data->key_seq[ KEY_CUTTER(change->sequence) & (CACHE_SIZE -1) ] = k;
    break;
  }

  kfree_rcu(change, rcu);

  LOG_DEBUG(change->packet_id, "async work complete");
}

static void psi_async_update_seq(struct work_struct *work)
{
	struct change_work * change = container_of(work, struct change_work, worker);
  int i, k;

  for(i=0, k = psi_cache_data->key_ino[ KEY_CUTTER(change->i_ino) & (CACHE_SIZE -1) ]; i<CACHE_SIZE; i++, k++)
  {
    if (k == CACHE_SIZE) k = 0;
    if (psi_cache_data->i_ino[k] != change->i_ino) continue;
    if (!psi_cache_data->inuse[k]) continue;
    if (psi_cache_data->sequence[k] == change->sequence) break; // no change needed

    psi_cache_data->sequence[k] = change->sequence;
    psi_cache_data->age[k] = change->age;
    break;
  }

  kfree_rcu(change, rcu);

  LOG_DEBUG(change->packet_id, "async work complete");
}

static void psi_async_update_age(struct work_struct *work)
{
	struct change_work * change = container_of(work, struct change_work, worker);
  int i, k;

  for(i=0, k = psi_cache_data->key_ino[ KEY_CUTTER(change->i_ino) & (CACHE_SIZE -1) ]; i<CACHE_SIZE; i++, k++)
  {
    if (k == CACHE_SIZE) k = 0;
    if (psi_cache_data->i_ino[k] != change->i_ino) continue;
    if (!psi_cache_data->inuse[k]) continue;

    psi_cache_data->age[k] = change->age;
    break;
  }

  kfree_rcu(change, rcu);

  LOG_DEBUG(change->packet_id, "async work complete");
}

static void psi_async_clearcache(struct work_struct *work)
{
	struct change_work * change = container_of(work, struct change_work, worker);

  memset(psi_cache_data, 0, sizeof(struct data_cache));

  kfree_rcu(change, rcu);

  LOG_DEBUG(change->packet_id, "async work complete");
}

////////////////////////

bool psi_from_inode(struct douane_psi * psi_out, const unsigned long i_ino, const uint32_t packet_id)
{
  int i, k;

  if (!psi_cache_data)
  {
    LOG_ERR(packet_id, "!psi_cache_data");
    return false;
  }

  LOG_DEBUG(packet_id, "searching for INO %lu", i_ino);

  for(i=0, k = psi_cache_data->key_ino[ KEY_CUTTER(i_ino) & (CACHE_SIZE -1) ]; i<CACHE_SIZE; i++, k++)
  {
    if (k == CACHE_SIZE) k = 0;
    if (psi_cache_data->i_ino[k] != i_ino) continue;
    if (!psi_cache_data->inuse[k]) continue;

    psi_out->i_ino = psi_cache_data->i_ino[k];
    psi_out->pid = psi_cache_data->pid[k];
    psi_out->sequence = psi_cache_data->sequence[k];
    strncpy(psi_out->process_path, psi_cache_data->path[k], PATH_LENGTH);

    LOG_DEBUG(packet_id, "found in slot %d", k);
    return true;
  }

  LOG_DEBUG(packet_id, "not found");
  return false;
}

bool psi_from_sequence(struct douane_psi * psi_out, const uint32_t sequence, const uint32_t packet_id)
{
  int i, k;

  if (!psi_cache_data)
  {
    LOG_ERR(packet_id, "!psi_cache_data");
    return false;
  }

  LOG_DEBUG(packet_id, "searching for SEQ %u", sequence);

  for(i=0, k = psi_cache_data->key_seq[ KEY_CUTTER(sequence) & (CACHE_SIZE -1) ]; i<CACHE_SIZE; i++, k++)
  {
    if (k == CACHE_SIZE) k = 0;
    if (!psi_cache_data->sequence[k]) continue;
    if ((psi_cache_data->sequence[k] != sequence) && ((psi_cache_data->sequence[k] + 1) != sequence)) continue;
    if (!psi_cache_data->inuse[k]) continue;

    psi_out->i_ino = psi_cache_data->i_ino[k];
    psi_out->pid = psi_cache_data->pid[k];
    psi_out->sequence = psi_cache_data->sequence[k];
    strncpy(psi_out->process_path, psi_cache_data->path[k], PATH_LENGTH);

    LOG_DEBUG(packet_id, "found in slot %d", k);
    return true;
  }

  LOG_DEBUG(packet_id, "not found");
  return false;
}

void psi_forget(const unsigned long i_ino, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }
  if (!psi_change_workq)
  {
    LOG_ERR(packet_id, "!psi_change_workq");
    return;
  }
  if (!psi_cache_data)
  {
    LOG_ERR(packet_id, "!psi_cache_data");
    return;
  }

  LOG_DEBUG(packet_id, "queuing async call to forget entry for INO %lu", i_ino);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  //
  INIT_WORK(&new_work->worker, psi_async_forget);

  spin_lock_bh(&psi_workq_lock);
  queue_work(psi_change_workq, &new_work->worker);
  spin_unlock_bh(&psi_workq_lock);
}

void psi_clear(const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  LOG_DEBUG(packet_id, "cleaning");

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }
  if (!psi_change_workq)
  {
    LOG_ERR(packet_id, "!psi_change_workq");
    return;
  }
  if (!psi_cache_data)
  {
    LOG_ERR(packet_id, "!psi_cache_data");
    return;
  }

  new_work->packet_id = packet_id;
  //
  INIT_WORK(&new_work->worker, psi_async_clearcache);

  spin_lock_bh(&psi_workq_lock);
  queue_work(psi_change_workq, &new_work->worker);
  spin_unlock_bh(&psi_workq_lock);
}

void psi_remember(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }
  if (!psi_change_workq)
  {
    LOG_ERR(packet_id, "!psi_change_workq");
    return;
  }
  if (!psi_cache_data)
  {
    LOG_ERR(packet_id, "!psi_cache_data");
    return;
  }

  LOG_DEBUG(packet_id, "queueing async call to remember entry INO %lu PID %d SEQ %u PATH %s", i_ino, pid, sequence, path);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  new_work->pid = pid;
  new_work->sequence = sequence;
  strncpy(new_work->path, path, PATH_LENGTH);
  new_work->path_hash = crc32(path);
  new_work->age = psi_cache_data->era;
  //
  INIT_WORK(&new_work->worker, psi_async_remember);

  spin_lock_bh(&psi_workq_lock);
  queue_work(psi_change_workq, &new_work->worker);
  spin_unlock_bh(&psi_workq_lock);
}

void psi_update_all(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }
  if (!psi_change_workq)
  {
    LOG_ERR(packet_id, "!psi_change_workq");
    return;
  }
  if (!psi_cache_data)
  {
    LOG_ERR(packet_id, "!psi_cache_data");
    return;
  }

  LOG_DEBUG(packet_id, "queueing async call to update_all for INO %lu", i_ino);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  new_work->pid = pid;
  new_work->sequence = sequence;
  strncpy(new_work->path, path, PATH_LENGTH);
  new_work->path_hash = crc32(path);
  new_work->age = psi_cache_data->era;
  //
  INIT_WORK(&new_work->worker, psi_async_update_all);

  spin_lock_bh(&psi_workq_lock);
  queue_work(psi_change_workq, &new_work->worker);
  spin_unlock_bh(&psi_workq_lock);
}

void psi_update_seq(const unsigned long i_ino, const uint32_t sequence, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }
  if (!psi_change_workq)
  {
    LOG_ERR(packet_id, "!psi_change_workq");
    return;
  }
  if (!psi_cache_data)
  {
    LOG_ERR(packet_id, "!psi_cache_data");
    return;
  }

  LOG_DEBUG(packet_id, "queueing async call to update_seq for INO %lu", i_ino);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  new_work->sequence = sequence;
  new_work->age = psi_cache_data->era;
  //
  INIT_WORK(&new_work->worker, psi_async_update_seq);

  spin_lock_bh(&psi_workq_lock);
  queue_work(psi_change_workq, &new_work->worker);
  spin_unlock_bh(&psi_workq_lock);
}

void psi_update_age(const unsigned long i_ino, const uint32_t packet_id)
{
  struct change_work * new_work = kzalloc(sizeof(struct change_work), GFP_ATOMIC);

  if (!new_work)
  {
    LOG_ERR(packet_id, "kzalloc failure");
    return;
  }
  if (!psi_change_workq)
  {
    LOG_ERR(packet_id, "!psi_change_workq");
    return;
  }
  if (!psi_cache_data)
  {
    LOG_ERR(packet_id, "!psi_cache_data");
    return;
  }

  LOG_DEBUG(packet_id, "queueing async call to update_age INO %lu", i_ino);

  new_work->packet_id = packet_id;
  new_work->i_ino = i_ino;
  new_work->age = psi_cache_data->era;
  //
  INIT_WORK(&new_work->worker, psi_async_update_age);

  spin_lock_bh(&psi_workq_lock);
  queue_work(psi_change_workq, &new_work->worker);
  spin_unlock_bh(&psi_workq_lock);
}

int psi_init(void)
{
  LOG_INFO(0, "process_socket cache %u entries %lu kb", CACHE_SIZE, sizeof(struct data_cache) / 1024);

  psi_cache_data = kzalloc(sizeof(struct data_cache), GFP_ATOMIC); // fixme
  if (!psi_cache_data)
  {
    LOG_ERR(0, "kzalloc failed");
    return -1;
  }

  // serialize all write-operations on the cache using a single, ordered queue
  psi_change_workq = alloc_ordered_workqueue("%s", WQ_HIGHPRI, "douane_cache");
  if (!psi_change_workq)
  {
    LOG_ERR(0, "alloc_ordered_workqueue failed");
    return -1;
  }

  return 0;
}

void psi_exit(void)
{
  // review: workq clear first?
  destroy_workqueue(psi_change_workq);
  psi_change_workq = NULL;

  kfree(psi_cache_data); // review: rcu?
}
