// eftirlit7 (gpl2) - orthopteroid@gmail.com
// forked from douane-lkms (gpl2) - zedtux@zedroot.org

// all logic in this file comes from https://gitlab.com/douaneapp/douane-dkms
// code-factoring and new bugs from orthopteroid@gmail.com

#include <linux/module.h>         // Needed by all modules
#include <linux/kernel.h>         // Needed for KERN_INFO
#include <linux/version.h>        // Needed for LINUX_VERSION_CODE >= KERNEL_VERSION
// ~~~~ Due to bug https://bugs.launchpad.net/ubuntu/+source/linux/+bug/929715 ~~~~
// #undef __KERNEL__
// #include <linux/netfilter_ipv4.h> // NF_IP_POST_ROUTING, NF_IP_PRI_LAST
// #define __KERNEL__
#define NF_IP_LOCAL_OUT 3
enum nf_ip_hook_priorities {
  NF_IP_PRI_LAST = INT_MAX
};
// ~~~~
#include <linux/netdevice.h>      // net_device
#include <linux/netfilter.h>      // nf_register_hook(), nf_unregister_hook(), nf_register_net_hook(), nf_unregister_net_hook()
#include <linux/netlink.h>        // NLMSG_SPACE(), nlmsg_put(), NETLINK_CB(), NLMSG_DATA(), NLM_F_REQUEST, netlink_unicast(), netlink_kernel_release(), nlmsg_hdr(), NETLINK_USERSOCK, netlink_kernel_create()

#include <linux/sched/signal.h>          // for_each_process(), task_lock(), task_unlock()

#include <linux/ip.h>             // ip_hdr()
#include <linux/udp.h>            // udp_hdr()
#include <linux/tcp.h>            // tcp_hdr()
#include <linux/fdtable.h>        // files_fdtable(), files_lookup_fd()
#include <linux/list.h>           // INIT_LIST_HEAD(), list_for_each_entry(), list_add_tail(), list_empty(), list_entry(), list_del(), list_for_each_entry_safe()
#include <linux/dcache.h>         // d_path()
#include <linux/skbuff.h>         // alloc_skb()
#include <linux/pid_namespace.h>  // task_active_pid_ns()
#include <linux/rculist.h>        // hlist_for_each_entry_rcu

#include "module.h"
#include "types.h"
#include "ksc.h"
#include "asc.h"

// related to lockup problems?
//#define DEBUG_TASKREF
#ifdef DEBUG_TASKREF
#define TASK_REFINC(t) get_task_struct(t)
#define TASK_REFDEC(t) put_task_struct(t)
#else
#define TASK_REFINC(t) do { } while(0)
#define TASK_REFDEC(t) do { } while(0)
#endif

// related to lockup problems?
//#define DEBUG_TASKLOCK
#ifdef DEBUG_TASKLOCK
#define TASK_LOCK(t) task_lock(t)
#define TASK_UNLOCK(t) task_unlock(t)
#else
#define TASK_LOCK(t) do { } while(0)
#define TASK_UNLOCK(t) do { } while(0)
#endif

// douane: has the concept of searching the process table but e7 added the ability of caching the results of this search.

#define ALIGNED ____cacheline_aligned

#define CACHE_KEY_MASK 0b11111111
#define KEY_CUTTER(v) ((v * 65437) + (v >> 6) + (v >> 13)) // 2^16-99, per https://primes.utm.edu/lists/2small/0bit.html

#define CACHE_FACTOR 2
#define CACHE_SLOTS (CACHE_FACTOR * (CACHE_KEY_MASK +1))
#define KEY_TO_SLOT(v) (CACHE_FACTOR * (KEY_CUTTER(v) & CACHE_KEY_MASK))

struct asc_data
{
  unsigned long  ino[CACHE_SLOTS] ALIGNED;
  pid_t          pid[CACHE_SLOTS] ALIGNED;
};

struct asc_data * asc_data = 0;

DEFINE_SPINLOCK(asc_lock);

bool asc_psi_from_ino(struct psi * psi_out, unsigned long socket_ino, const uint32_t packet_id)
{
  struct file * file = NULL;
  struct inode * inode = NULL;
  struct socket * socket_ = NULL;
  struct sock * sock_ = NULL;
  struct task_struct * task = NULL;
  struct task_struct * found_task = NULL; // refcounted when found
  struct pid * pid_struct = NULL;
  pid_t found_pid = 0;
  int name_str_len;
  int i = 0, k = 0, e = 0;
  //
  char * deleted_str = " (deleted)";
  int deleted_str_len = 10;

  spin_lock_bh(&asc_lock);
  rcu_read_lock();

  for(i = 0, k = KEY_TO_SLOT(socket_ino); i<CACHE_SLOTS; ++i, ++k)
  {
    if(k == CACHE_SLOTS) k = 0;
    if(asc_data->ino[k] != socket_ino) continue;

    pid_struct = find_get_pid(asc_data->pid[k]);
    if(!pid_struct)
    {
      asc_data->ino[k] = 0;
      asc_data->pid[k] = 0;

      LOG_DEBUG(packet_id, "searching for INO %ld - orphaned", socket_ino);
      goto refresh_cache;
    }

    task = get_pid_task(pid_struct, PIDTYPE_PID);
    if(!task)
    {
      LOG_ERR(packet_id, "invalid task info");
      goto refresh_cache;
    }

    TASK_REFINC(task);
    found_task = task;
    found_pid = asc_data->pid[k];

    LOG_DEBUG(packet_id, "searching for INO %ld - found in cache with PID %d", socket_ino, found_pid);
    goto out_found;
  }

refresh_cache:

  // clean cache
  for(i = 0; i < CACHE_SLOTS; i++) asc_data->ino[i] = 0;

  // refresh
  for_each_process(task)
  {
    TASK_REFINC(task);
    TASK_LOCK(task);
    if (task->files)
    {
      unsigned int fd_i = 0;
      unsigned int fd_max = files_fdtable(task->files)->max_fds;

      for(fd_i = 0; fd_i < fd_max; fd_i++)
      {
        if(!(file = files_lookup_fd_rcu(task->files, fd_i))) continue;
        if(!(inode = file_inode(file))) continue;
        if(!S_ISSOCK(inode->i_mode)) continue; // not a socket file
        if(!(socket_= SOCKET_I(inode))) continue;
        if(!(sock_ = socket_->sk)) continue;
        if(sock_->sk_family != PF_INET) continue; // not inet socket

        if (!found_task && !found_pid && (inode->i_ino == socket_ino))
        {
          found_task = task; // nb: don't refinc, already ref'd
          found_pid = task->pid;

          LOG_DEBUG(packet_id, "searching for INO %ld - found in process table with PID %d", socket_ino, found_pid);
        }

        for(i = 0, k = KEY_TO_SLOT(inode->i_ino); i<CACHE_SLOTS; ++i, ++k)
        {
          if(k == CACHE_SLOTS) k = 0;
          if(asc_data->ino[k] == 0)
          {
            asc_data->ino[k] = inode->i_ino;
            asc_data->pid[k] = task->pid;
            e++;
            break;
          }
        }
        if(i == CACHE_SLOTS)
        {
          LOG_ERR(packet_id, "unable to fill cache for INO %ld PID %d - cache too small?", file_inode(file)->i_ino, task->pid);
        }
      }
    }
    TASK_UNLOCK(task);
    TASK_REFDEC(task);
  }
  LOG_DEBUG(packet_id, "cache refreshed - %d entries", e);

out_found:
  // if (found_task) then it will be ref'd
  if(!found_task)
  {
    rcu_read_unlock();
    spin_unlock_bh(&asc_lock);

    if(psi_out->process_path[0]!=0)
    {
      LOG_DEBUG(packet_id, "searching for INO %ld - not found. fallback to %s", socket_ino, psi_out->process_path);
      return true;
    }

    LOG_DEBUG(packet_id, "searching for INO %ld - not found", socket_ino);
    return false;
  }

  TASK_LOCK(found_task); // todo: increase code locality of LOCK/UNLOCK
  if(!(found_task->mm) || !(found_task->mm->exe_file))
  {
    TASK_UNLOCK(found_task);
    TASK_REFDEC(found_task);
    rcu_read_unlock();
    spin_unlock_bh(&asc_lock);

    if(psi_out->process_path[0]!=0)
    {
      LOG_DEBUG(packet_id, "searching for INO %ld - mm error. fallback to %s", socket_ino, psi_out->process_path);
      return true;
    }

    LOG_ERR(packet_id, "mm ERROR");
    return false;
  }

  {
    // notes:
    // - d_path might return string with " (deleted)" suffix
    // - d_path might return string with garbage prefix
    char * p = d_path(&found_task->mm->exe_file->f_path, psi_out->process_path, PATH_LENGTH);

    TASK_UNLOCK(found_task);
    TASK_REFDEC(found_task);
    rcu_read_unlock();
    spin_unlock_bh(&asc_lock);

    if (IS_ERR(p))
    {
      LOG_ERR(packet_id, "d_path returned ERROR");
      return false;
    }

    psi_out->pid = found_pid;
    if(psi_out->process_path != p)
    {
      // start of string is not start of buffer, so strip prefix
      strncpy(psi_out->process_path, p, PATH_LENGTH - (p - psi_out->process_path) +1); // +1 includes \0
    }
  }

  // check for " (deleted)" suffix and strip it
  name_str_len = strnlen(psi_out->process_path, PATH_LENGTH);
  if (name_str_len > deleted_str_len)
  {
    // long enough for a suffix
    int suffix_position = name_str_len - deleted_str_len;
    if (0 == strncmp(psi_out->process_path + suffix_position, deleted_str, deleted_str_len))
    {
      memset(psi_out->process_path + suffix_position, 0, deleted_str_len);
    }
  }

  return true;
}

bool asc_psi_from_ino_pid(struct psi * psi_out, unsigned long socket_ino, pid_t pid, const uint32_t packet_id)
{
  struct file * file = NULL;
  struct inode * inode = NULL;
  struct pid * pid_struct = NULL;
  struct task_struct * task = NULL;
  unsigned int fd_i;
  unsigned int fd_max;

  rcu_read_lock();

  pid_struct = find_get_pid(pid);
  if(!pid_struct)
  {
    LOG_DEBUG(packet_id, "searching for INO %ld in PID %d - process not found", socket_ino, pid);
    rcu_read_unlock();
    return false;
  }

  task = get_pid_task(pid_struct, PIDTYPE_PID);
  if(!task)
  {
    LOG_ERR(packet_id, "invalid task info");
    rcu_read_unlock();
    return false;
  }

  TASK_REFINC(task);
  TASK_LOCK(task);
  if(!(task->files))
  {
    LOG_DEBUG(packet_id, "searching for INO %ld in PID %d - no files", socket_ino, pid);
    TASK_UNLOCK(task);
    TASK_REFDEC(task);
    rcu_read_unlock();
    return false;
  }

  // douane: almost verbatim, but e7 streamlined and removed the heuristics
  fd_max = files_fdtable(task->files)->max_fds;
  for(fd_i = 0; fd_i < fd_max; fd_i++)
  {
    if(!(file = files_lookup_fd_rcu(task->files, fd_i))) continue;
    if(!(inode = file_inode(file))) continue;
    if(!S_ISSOCK(inode->i_mode)) continue; // not a socket file
    if(inode->i_ino != socket_ino) continue;

    goto out_found;
  }

  LOG_DEBUG(packet_id, "searching for INO %ld in PID %d - not found", socket_ino, pid);

  TASK_UNLOCK(task);
  TASK_REFDEC(task);
  rcu_read_unlock();
  return false;

out_found:
  if(!(task->mm) || !(task->mm->exe_file))
  {
    TASK_UNLOCK(task);
    TASK_REFDEC(task);
    rcu_read_unlock();

    if(psi_out->process_path[0]!=0)
    {
      LOG_DEBUG(packet_id, "searching for INO %ld - mm error. fallback to %s", socket_ino, psi_out->process_path);
      return true;
    }

    LOG_ERR(packet_id, "mm ERROR");
    return false;
  }

  // douane: use of d_path to extract process name
  {
    // notes:
    // - d_path might return string with " (deleted)" suffix
    // - d_path might return string with garbage prefix
    char * p = d_path(&task->mm->exe_file->f_path, psi_out->process_path, PATH_LENGTH);

    TASK_UNLOCK(task);
    TASK_REFDEC(task);
    rcu_read_unlock();

    if (IS_ERR(p))
    {
      LOG_ERR(packet_id, "d_path returned ERROR");
      return false;
    }

    psi_out->pid = pid;
    if(psi_out->process_path != p)
    {
      // start of string is not start of buffer, so strip prefix
      strncpy(psi_out->process_path, p, PATH_LENGTH - (p - psi_out->process_path) +1); // +1 includes \0
    }
  }

  // douane: need to strip " (deleted)" suffix but e7 streamlined this code
  {
    char * deleted_str = " (deleted)";
    int deleted_str_len = 10;
    // check for " (deleted)" suffix and strip it
    int name_str_len = strnlen(psi_out->process_path, PATH_LENGTH);
    if (name_str_len > deleted_str_len)
    {
      // long enough for a suffix
      int suffix_position = name_str_len - deleted_str_len;
      if (0 == strncmp(psi_out->process_path + suffix_position, deleted_str, deleted_str_len))
      {
        memset(psi_out->process_path + suffix_position, 0, deleted_str_len);
      }
    }
  }

  LOG_DEBUG(packet_id, "searching for INO %ld in PID %d - found", socket_ino, pid);

  return true;
}

bool asc_pid_owns_ino(unsigned long socket_ino, pid_t pid, const uint32_t packet_id)
{
  struct pid * pid_struct = NULL;
  struct task_struct * task = NULL;
  struct file * file = NULL;
  bool rc = false;

  rcu_read_lock();

  pid_struct = find_get_pid(pid);
  if(!pid_struct)
  {
    LOG_DEBUG(packet_id, "searching for INO %ld in PID %d - process not found", socket_ino, pid);
    rcu_read_unlock();
    return false;
  }

  task = get_pid_task(pid_struct, PIDTYPE_PID);
  if(!task)
  {
    LOG_ERR(packet_id, "invalid task info");
    rcu_read_unlock();
    return false;
  }

  TASK_REFINC(task);
  TASK_LOCK(task);
  if(!(task->files))
  {
    LOG_DEBUG(packet_id, "searching for INO %ld in PID %d - no files", socket_ino, pid);
    goto out;
  }

  {
    // douane: almost verbatim, but e7 streamlined and removed the heuristics
    unsigned int fd_i = 0;
    unsigned int fd_max = files_fdtable(task->files)->max_fds;
    for(fd_i = 0; fd_i < fd_max; fd_i++)
    {
      if (!(file = files_lookup_fd_rcu(task->files, fd_i))) continue;
      if (!S_ISSOCK(file_inode(file)->i_mode)) continue; // not a socket file
      if (file_inode(file)->i_ino != socket_ino) continue;

      LOG_DEBUG(packet_id, "searching PID %d for INO %ld - found", pid, socket_ino);

      rc = true;
      goto out;
    }
  }
  // this may be happening when a socket is closed at the time the last packet is received...
  LOG_DEBUG(packet_id, "searching PID %d for INO %ld - not found", pid, socket_ino);

out:
  TASK_UNLOCK(task);
  TASK_REFDEC(task);
  rcu_read_unlock();
  return rc;
}

//////////////////

int asc_init(void)
{
  LOG_INFO(0, "cache %u entries %lu kb", CACHE_SLOTS, sizeof(struct asc_data) / 1024);
  asc_data = kzalloc(sizeof(struct asc_data), GFP_ATOMIC); // fixme
  if (!asc_data)
  {
    LOG_ERR(0, "kzalloc failed");
    return -1;
  }
  return 0;
}

void asc_exit(void)
{
  kfree(asc_data);
}
