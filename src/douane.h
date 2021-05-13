#ifndef _DOUANE_H_
#define _DOUANE_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

void douane_enable_set(bool value, const uint32_t stack_id);
void douane_enable_get(bool * value_out, const uint32_t stack_id);
void douane_logging_set(bool value, const uint32_t stack_id);
void douane_logging_get(bool * value_out, const uint32_t stack_id);

int douane_init(void);
void douane_exit(void);

#endif // _DOUANE_H_
