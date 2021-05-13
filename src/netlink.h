#ifndef _NETLINK_H_
#define _NETLINK_H

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

struct dnl_recvfns
{
  void(*recv_echo)(const char * message, const uint32_t stack_id);

  void(*enable_set)(bool value, const uint32_t stack_id);
  void(*enable_get)(bool * value_out, const uint32_t stack_id);
  void(*logging_set)(bool value, const uint32_t stack_id);
  void(*logging_get)(bool * value_out, const uint32_t stack_id);

  void(*rule_add)(const struct douane_rule * rule, const uint32_t stack_id);
  void(*rules_clear)(const uint32_t stack_id);
  void(*rules_query)(const uint32_t stack_id);
};

int dnl_send_echo(const char * message, const uint32_t stack_id);

int dnl_send_bye(const uint32_t stack_id);
int dnl_send_event(const char * process, const char * device, const uint32_t stack_id);
int dnl_send_rules(int count, const struct douane_rule * rules, const uint32_t stack_id);

int dnl_init(struct dnl_recvfns * rfns);
void dnl_exit(void);

#endif // _NETLINK_H_
