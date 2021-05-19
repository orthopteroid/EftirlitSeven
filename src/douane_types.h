#ifndef _DOUANE_TYPES_H_
#define _DOUANE_TYPES_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

#define PATH_LENGTH 129

// psi is the type douane uses to cache and associate: process-name X process-id X tcp-sequence-no X inode
struct douane_psi
{
  unsigned long i_ino;                     // Process socket file inode // todo: get the right type here...
  pid_t         pid;                       // PID of the process
  char          process_path[PATH_LENGTH +1]; // Path of the process, +1 for null
  uint32_t      sequence;                  // TCP sequence (Is be 0 for non TCP packets)
};

struct douane_rule
{
  char process_path[PATH_LENGTH +1];
  bool allowed;
};

// rcu-friendly variable size array of rules
struct douane_ruleset_rcu
{
  struct rcu_head rcu;
  //
  int count;
  struct douane_rule rules[];
};

#endif // _DOUANE_TYPES_H_
