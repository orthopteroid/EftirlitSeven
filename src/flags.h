#ifndef _FLAGS_H_
#define _FLAGS_H_

extern uint32_t flag_value[];

extern const char* flag_name[];

int flag_lookup(const char* name);

int flag_init();
void flag_exit(void);

#endif // _FLAGS_H_
