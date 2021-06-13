#ifndef _DOUANE_H_
#define _DOUANE_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

// packet actions are:
// IGNORE -1
//#define NF_DROP 0
//#define NF_ACCEPT 1
//#define NF_STOLEN 2
//#define NF_QUEUE 3
//#define NF_REPEAT 4
//#define NF_STOP 5

enum {
  DOUANE_FLAGS_FIRST,

  // IGNORE (firewall enabled), ACCEPT (firewall disable) or DROP (lockout mode)
  DOUANE_EARLY_ACTION = DOUANE_FLAGS_FIRST,  // IGNORE or NF_xxx

  // for kernels without debugfs, this can help in debugging
  DOUANE_ENABLE_LKM_DEBUG,

  // failure mode handling (usually ACCEPT)
  // when firewall is enabled these can be a cause of packet leaks when set to ACCEPT
  DOUANE_FAILPATH_ACTION,
  DOUANE_UNKN_PROCESS_ACTION,
  DOUANE_UNKN_PROTOCOL_ACTION,

  // flags for packet and daemon events during rule processing
  DOUANE_RULE_QUERY_EVENTS, // notify daemon of packets that have no rule (usually 1)
  DOUANE_RULE_QUERY_ACTION, // what to do with a packet that has no rule (ACCEPT) todo: QUEUE
  DOUANE_RULE_DROP_EVENTS, // notify daemon when a packet is DROPPED due to a rule (usually 0)
  DOUANE_RULE_ACCEPT_EVENTS, // notify daemon when a packet is ACCEPTED due to a rule (usually 0)

  DOUANE_FLAGS_LAST = DOUANE_RULE_ACCEPT_EVENTS,
  DOUANE_FLAGS_COUNT = DOUANE_FLAGS_LAST +1
};

void douane_flag_set(int flag, int value, const uint32_t packet_id);
void douane_flag_get(int flag, int * value_out, const uint32_t packet_id);

int douane_init(void);
void douane_exit(void);

#endif // _DOUANE_H_
