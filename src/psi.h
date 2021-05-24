#ifndef _PSI_H_
#define _PSI_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

// used to cache and associate: process-name X process-id X tcp-sequence-no X inode
struct psi_struct
{
  unsigned long i_ino;                     // Process socket file inode // todo: get the right type here...
  pid_t         pid;                       // PID of the process
  char          process_path[PATH_LENGTH +1]; // Path of the process, +1 for null
  uint32_t      sequence;                  // TCP sequence (Is be 0 for non TCP packets)
};

bool psi_from_inode(struct psi_struct * psi_out, const unsigned long i_ino, const uint32_t packet_id);
bool psi_from_sequence(struct psi_struct * psi_out, const uint32_t sequence, const uint32_t packet_id);
void psi_clear(const uint32_t packet_id);
void psi_forget(const unsigned long i_ino, const uint32_t packet_id);
void psi_remember(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id);
void psi_update_all(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id);
void psi_update_seq(const unsigned long i_ino, const uint32_t sequence, const uint32_t packet_id);
void psi_update_age(const unsigned long i_ino, const uint32_t packet_id);

int psi_init(void);
void psi_exit(void);

#endif // _PSI_H_
