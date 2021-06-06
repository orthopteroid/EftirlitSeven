#ifndef _PI_H_
#define _PI_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com

// lookup socket inodes for all process ids in a cache
// refresh cache from process table when there is a cache-miss
bool pi_psi_from_ino(struct psi_struct * psi_out, unsigned long socket_ino, const uint32_t packet_id);

bool pi_psi_from_ino_pid(struct psi_struct * psi_out, unsigned long socket_ino, pid_t pid, const uint32_t packet_id);

int pi_init(void);
void pi_exit(void);

#endif // _PI_H_
