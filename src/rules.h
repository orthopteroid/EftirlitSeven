#ifndef _RULES_H_
#define _RULES_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

void rules_print(const uint32_t packet_id);
void rules_append(const char * process_path, const bool is_allowed, const uint32_t packet_id);
void rules_clear(const uint32_t packet_id);
void rules_remove(const unsigned char * process_path, const uint32_t packet_id);
int rules_search(struct douane_rule * rule_out, const unsigned char * process_path, const uint32_t packet_id);

int rules_get(struct douane_ruleset_rcu ** ruleset_out_rcufree, const uint32_t packet_id);

#endif // _RULES_H_
