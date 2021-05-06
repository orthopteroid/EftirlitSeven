#ifndef _DOUANE_TYPES_H_
#define _DOUANE_TYPES_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

#define KIND_HAND_SHAKE   1
#define KIND_SENDING_RULE 2
#define KIND_GOODBYE      3
#define KIND_DELETE_RULE  4

#define PATH_LENGTH 129

// raw netlink-io packet to douane-daemon
// nb: this revision has smaller process_path so-as to allow kfree_rcu usage
struct douane_nlpacket {
  int   kind;                         // Deamon -> LKM  | Define which kind of message it is
  char  process_path[PATH_LENGTH +1]; // Bidirectional  | Related process path, +1 for \0
  int   allowed;                      // Deamon -> LKM  | Define if the process is allowed to outgoing network traffic or not
  char  device_name[16];              // Bidirectional  | Device name where the packet has been detected (IFNAMSIZ = 16)
  int   protocol;                     // LKM -> Deamon  | Protocol id of the detected outgoing network activity
  char  ip_source[16];                // LKM -> Deamon  | Outgoing network traffic ip source
  int   port_source;                  // LKM -> Deamon  | Outgoing network traffic port source
  char  ip_destination[16];           // LKM -> Deamon  | Outgoing network traffic ip destination
  int   port_destination;             // LKM -> Deamon  | Outgoing network traffic port destination
  int   size;                         // LKM -> Deamon  | Size of the packet
};

// psi is the type douane uses to cache and associate: process-name X process-id X tcp-sequence-no X inode
struct douane_psi
{
  unsigned long     i_ino;                     // Process socket file inode
  pid_t             pid;                       // PID of the process
  char              process_path[PATH_LENGTH +1]; // Path of the process, +1 for null
  uint32_t          sequence;                  // TCP sequence (Is be 0 for non TCP packets)
};

struct douane_rule
{
  char              process_path[PATH_LENGTH +1];
  bool              allowed;
  //
  struct list_head  list;
  struct rcu_head   rcu;
};

#endif // _DOUANE_TYPES_H_
