#ifndef _RULES_H_
#define _RULES_H_

// eftirlit7 (gpl2) - orthopteroid@gmail.com
// forked from douane-lkms (gpl2) - zedtux@zedroot.org

struct rule_struct
{
  uint32_t protocol;
  char process_path[PATH_LENGTH +1];
  bool allowed;
};

// rcu-friendly variable size array of rules
struct ruleset_struct_rcu
{
  struct rcu_head rcu;
  //
  int count;
  struct rule_struct rules[];
};

void rules_clear(const uint32_t packet_id);
void rules_clear_state(const bool is_allowed, const uint32_t packet_id);

bool rules_add(uint32_t protocol, const char * process_path, const bool is_allowed, const uint32_t packet_id);
bool rules_remove(uint32_t protocol, const char * process_path, const uint32_t packet_id);

bool rules_search(struct rule_struct * rule_out, uint32_t protocol, const char * process_path, const uint32_t packet_id);

int rules_get(struct ruleset_struct_rcu ** ruleset_out_rcufree, const uint32_t packet_id);

int rules_init(void);
void rules_exit(void);

#endif // _RULES_H_
