#ifndef _KSC_H_
#define _KSC_H_

// eftirlit7 (gpl2) - orthopteroid@gmail.com

// lookup a socket in a known-socket-cache

bool ksc_from_inode(struct psi * psi_out, const unsigned long i_ino, const uint32_t packet_id);
bool ksc_from_sequence(struct psi * psi_out, const uint32_t sequence, const uint32_t packet_id);
void ksc_clear(const uint32_t packet_id);
void ksc_forget(const unsigned long i_ino, const uint32_t packet_id);
void ksc_remember(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id);
void ksc_update_all(const unsigned long i_ino, const uint32_t sequence, const pid_t pid, const char * path, const uint32_t packet_id);
void ksc_update_seq(const unsigned long i_ino, const uint32_t sequence, const uint32_t packet_id);
void ksc_update_age(const unsigned long i_ino, const uint32_t packet_id);

int ksc_init(void);
void ksc_exit(void);

#endif // _KSC_H_
