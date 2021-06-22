#ifndef __TYPES_H_
#define __TYPES_H_

// douane: a core type and the main structure used for remembering sockets in an rcu_list
// used to cache and associate: process-name X process-id X tcp-sequence-no X inode
struct psi
{
  unsigned long i_ino;                     // Process socket file inode // todo: get the right type here...
  pid_t         pid;                       // PID of the process
  char          process_path[PATH_LENGTH +1]; // Path of the process, +1 for null
  uint32_t      sequence;                  // TCP sequence (Is be 0 for non TCP packets)
};

#endif // __TYPES_H_
