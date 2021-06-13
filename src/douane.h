#ifndef _DOUANE_H_
#define _DOUANE_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

enum {
  DOUANE_FLAGS_FIRST,
  DOUANE_EARLY_ACTION = DOUANE_FLAGS_FIRST,  // NF_xxx
  DOUANE_ENABLE_LKM_DEBUG,
  DOUANE_FAILPATH_ACTION, // NF_xxx
  DOUANE_UNKN_PROCESS_ACTION, // NF_xxx
  DOUANE_UNKN_PROTOCOL_ACTION, // NF_xxx
  DOUANE_RULE_QUERY_EVENTS,
  DOUANE_RULE_QUERY_ACTION, // NF_xxx
  DOUANE_RULE_DROP_EVENTS,
  DOUANE_RULE_ACCEPT_EVENTS,
  DOUANE_FLAGS_LAST = DOUANE_RULE_ACCEPT_EVENTS,
  DOUANE_FLAGS_COUNT = DOUANE_FLAGS_LAST +1
};

void douane_flag_set(int flag, int value, const uint32_t packet_id);
void douane_flag_get(int flag, int * value_out, const uint32_t packet_id);

int douane_init(void);
void douane_exit(void);

#endif // _DOUANE_H_
