// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

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
#include <linux/fdtable.h>        // files_fdtable(), fcheck_files()
#include <linux/list.h>           // INIT_LIST_HEAD(), list_for_each_entry(), list_add_tail(), list_empty(), list_entry(), list_del(), list_for_each_entry_safe()
#include <linux/dcache.h>         // d_path()
#include <linux/skbuff.h>         // alloc_skb()
#include <linux/pid_namespace.h>  // task_active_pid_ns()
#include <linux/rculist.h>        // hlist_for_each_entry_rcu

#include "module.h"
#include "psi.h"
#include "pi.h"

#define ALIGNED ____cacheline_aligned

// cache size is paired with the key cutter size
#define CACHE_SIZE 4096 // 12 bits
#define KEY_CUTTER(v) (v ^ (v >> 12) ^ (v >> 24))

struct pi_cache
{
  unsigned long  ino[CACHE_SIZE] ALIGNED;
  pid_t          pid[CACHE_SIZE] ALIGNED;
};

struct pi_cache * pi_cache = 0;

DEFINE_SPINLOCK(pi_lock);

bool pi_psi_from_ino(struct psi_struct * psi_out, unsigned long socket_ino, const uint32_t packet_id)
{
  struct task_struct * task;
  struct task_struct * found_task = 0;
  pid_t found_pid = 0;
  int name_str_len;
  int i = 0, j = 0;
  //
  char * deleted_str = " (deleted)";
  int deleted_str_len = 10;

  rcu_read_lock();

  spin_lock_bh(&pi_lock);

  j = KEY_CUTTER(socket_ino) % CACHE_SIZE;
  for(i=0; i<CACHE_SIZE; i++, j++)
  {
    if(j == CACHE_SIZE) j = 0;
    if(pi_cache->ino[j] == socket_ino)
    {
      struct pid * pid_struct = find_get_pid(pi_cache->pid[j]);
      found_task = pid_struct ? get_pid_task(pid_struct, PIDTYPE_PID) : NULL;
      found_pid = task->pid;

      spin_unlock_bh(&pi_lock);

      if(!found_task)
      {
        LOG_ERR(packet_id, "invalid task info");
        goto out_fail;
      }

      LOG_DEBUG(packet_id, "found INO %ld PID %d in cache", socket_ino, found_pid);
      goto out_found;
    }
  }

  // clean cache
  for(i=0; i<CACHE_SIZE; i++) pi_cache->ino[i] = 0;

  // refresh
  for_each_process(task)
  {
    if (task->files)
    {
      unsigned int fd_i = 0;
      unsigned int fd_max = files_fdtable(task->files)->max_fds;

      for(fd_i = 0; fd_i < fd_max; fd_i++)
      {
        struct file * file = fcheck_files(task->files, fd_i);
        if (!file) continue;
        if (!S_ISSOCK(file_inode(file)->i_mode)) continue; // not a socket file
        if (file_inode(file)->i_ino == socket_ino)
        {
          found_task = task;
          found_pid = task->pid;
        }

        j = KEY_CUTTER(file_inode(file)->i_ino) % CACHE_SIZE;
        for(i=0; i<CACHE_SIZE; i++, j++)
        {
          if(j == CACHE_SIZE) j = 0;
          if(pi_cache->ino[j] == 0)
          {
            pi_cache->ino[j] = file_inode(file)->i_ino;
            pi_cache->pid[j] = task->pid;
            goto filled;
          }
        }
        LOG_ERR(packet_id, "unable to fill cache for INO %ld PID %d - cache too small?", file_inode(file)->i_ino, task->pid);

filled:
        ; // dear dog shoot me
      }
    }
  }

  spin_unlock_bh(&pi_lock);

  if(found_task && found_task->mm && found_task->mm->exe_file)
  {
    LOG_DEBUG(packet_id, "found INO %ld PID %d in process table", socket_ino, found_pid);
    goto out_found;
  }

out_fail:
  LOG_DEBUG(packet_id, "searching for INO %ld - not found", socket_ino);

  rcu_read_unlock();
  return false;

out_found:
  {
    char * p;

    // notes:
    // - d_path might return string with " (deleted)" suffix
    // - d_path might return string with garbage prefix
    p = d_path(&found_task->mm->exe_file->f_path, psi_out->process_path, PATH_LENGTH);
    if (IS_ERR(p))
    {
      LOG_ERR(packet_id, "d_path returned ERROR");
      goto out_fail;
    }

    psi_out->pid = found_pid;
    if(psi_out->process_path != p)
    {
      // start of string is not start of buffer, so strip prefix
      strncpy(psi_out->process_path, p, PATH_LENGTH - (p - psi_out->process_path) +1); // +1 includes \0
    }
  }

  rcu_read_unlock();

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

//////////////////

int pi_init(void)
{
  LOG_INFO(0, "pi_cache %u entries %lu kb", CACHE_SIZE, sizeof(struct pi_cache) / 1024);
  pi_cache = kzalloc(sizeof(struct pi_cache), GFP_ATOMIC); // fixme
  if (!pi_cache)
  {
    LOG_ERR(0, "kzalloc failed");
    return -1;
  }
  return 0;
}

void pi_exit(void)
{
  kfree(pi_cache);
}
