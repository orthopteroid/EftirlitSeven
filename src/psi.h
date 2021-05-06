#ifndef _PSI_H_
#define _PSI_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

bool psi_from_inode(struct douane_psi * psi_out, const unsigned long i_ino, const uint32_t packet_id);
bool psi_from_sequence(struct douane_psi * psi_out, const uint32_t sequence, const uint32_t packet_id);
void psi_clear(const uint32_t packet_id);
void psi_forget(const unsigned long i_ino, const uint32_t packet_id);
void psi_remember(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id);
void psi_update_all(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id);
void psi_update_seq(const unsigned long i_ino, const uint32_t sequence, const uint32_t packet_id);
void psi_update_age(const unsigned long i_ino, const uint32_t packet_id);

int psi_init(void);
void psi_exit(void);

#endif // _PSI_H_
