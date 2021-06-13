#ifndef _NETLINK_H_
#define _NETLINK_H

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

struct enl_recvfns
{
  void(*recv_echo)(const char * message, const uint32_t stack_id);

  void(*flag_set)(int flag, int value, const uint32_t stack_id);
  void(*flag_get)(int flag, int * value_out, const uint32_t stack_id);

  void(*rule_add)(const struct rule_struct * rule, const uint32_t stack_id);
  void(*rules_clear)(const uint32_t stack_id);
  void(*rules_query)(const uint32_t stack_id);
};

int enl_send_echo(const char * message, const uint32_t stack_id);

int enl_send_bye(const uint32_t stack_id);
int enl_send_event(const char * process, const char * device, bool allowed, const uint32_t stack_id);
int enl_send_rules(int count, const struct rule_struct * rules, const uint32_t stack_id);

int enl_init(struct enl_recvfns * rfns);
void enl_exit(void);

#endif // _NETLINK_H_
