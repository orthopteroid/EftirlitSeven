#ifndef _NETLINK_H_
#define _NETLINK_H

// eftirlit7 (gpl3) - orthopteroid@gmail.com

int enl_send_disconnect(const uint32_t stack_id);
int enl_send_event(uint32_t state, uint32_t prot, const char * path, const uint32_t stack_id);

int enl_is_connected(void);

int enl_init(void);
void enl_exit(void);

#endif // _NETLINK_H_
