#ifndef _ASC_H_
#define _ASC_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com

// lookup a socket from the process table (or possibly somewhere else) or a cache-of-thereof.
// (this api is geared towards finding sockets we've never seen before so access is probably slower)

// lookup socket inodes for all process ids in a cache
// refresh cache from process table when there is a cache-miss
bool asc_psi_from_ino(struct psi * psi_out, unsigned long socket_ino, const uint32_t packet_id);

bool asc_psi_from_ino_pid(struct psi * psi_out, unsigned long socket_ino, pid_t pid, const uint32_t packet_id);

bool asc_pid_owns_ino(unsigned long socket_ino, pid_t pid, const uint32_t packet_id);

int asc_init(void);
void asc_exit(void);

#endif // _ASC_H_
