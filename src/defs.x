E7X_NAME(eftirlit)
E7X_VERSION(1)

// basic attribs:
// NESTED
// PATH: string
// FLAG: E7F_...
// STATE: E7C_BLOCK, E7C_ALLOW, E7C_PENDING*  (*unimplemented)
// PROT, VALUE: uint32
//
// * main firewall state commands
// DISCONNECT - lkm shutting down
//
// * rule management commands
// BLOCK [ PROT ] [ PATH ]
// ALLOW [ PROT ] [ PATH ]
// ENABLE
// CLEAR [ STATE ] | ( [ PROT ] [ PATH ] )
// QUERY - returns QUERY STATE [ PROT ] [ PATH ] [ NESTED ]
//
// * outbound connection attempts
// EVENT PROT PATH STATE - requires BLOCK or ALLOW reply
//
// * internal flag management commands
// SET FLAG VALUE
// GET FLAG - returns GET FLAG VALUE
//
// NB on aliases:
// these are identifiers used in the daemon ui to represent a uint32 value
// for the LKM. They have bnf prefixes:
// a = action (E7C_ALLOW, E7C_BLOCK)
// n = boolean for notification (E7C_DISABLED, E7C_ENABLED)
// c = constant (their own value)
// e = enumeration of mulitple types of values

// ID, e7d alias and constant value
E7X_CONST(E7C_IP_ICMP,  "cicmp",     IPPROTO_ICMP)
E7X_CONST(E7C_IP_TCP,   "ctcp",      IPPROTO_TCP)
E7X_CONST(E7C_IP_UDP,   "cudp",      IPPROTO_UDP)
E7X_CONST(E7C_IP_ANY,   "cany",      ~0)
E7X_CONST(E7C_BLOCK,    "cblock",    0xFF00)
E7X_CONST(E7C_ALLOW,    "callow",    0xFF01)
E7X_CONST(E7C_PENDING,  "cpending",  0xFF02)
E7X_CONST(E7C_ENABLED,  "cenabled",  0xFF03)
E7X_CONST(E7C_DISABLED, "cdisabled", 0xFF04)

// ID, e7d alias and default LKM value
E7X_FLAG(E7F_MODE,                 "emode",    E7C_DISABLED)  // E7C_ENABLED, E7C_DISABLED, E7C_BLOCK
E7X_FLAG(E7F_DEBUG,                "ndebug",   E7C_ENABLED)
E7X_FLAG(E7F_FAILPATH_ACTION,      "afail",    E7C_ALLOW)
E7X_FLAG(E7F_UNKN_PROCESS_ACTION,  "aunkproc", E7C_ALLOW)
E7X_FLAG(E7F_UNKN_PROTOCOL_ACTION, "aunkprot", E7C_ALLOW)
E7X_FLAG(E7F_NORULE_NOTIFY,        "nnorule",  E7C_ENABLED)   // notify daemon of packets that have no rule
E7X_FLAG(E7F_NORULE_SQUELCH,       "nsquelch", E7C_ENABLED)   // squelch between E7F_NORULE_NOTIFY for each (proto,path) pair
E7X_FLAG(E7F_NORULE_ACTION,        "aunkrule", E7C_ALLOW)     // what to do with a packet that has no rule (ACCEPT) todo: QUEUE
E7X_FLAG(E7F_RULE_DROPS,           "ndrops",   E7C_DISABLED)  // notify daemon when a packet is DROPPED due to a rule
E7X_FLAG(E7F_RULE_ACCEPTS,         "naccepts", E7C_DISABLED)  // notify daemon when a packet is ACCEPTED due to a rule
E7X_FLAG(E7F_RULE_CHANGE_QUERY,    "nrchngq",  E7C_ENABLED)   // notify daemon with full query when rules are added/removed

E7X_COMM(ENL_COMM_ERROR)
E7X_COMM(ENL_COMM_DISCONNECT)
E7X_COMM(ENL_COMM_BLOCK)
E7X_COMM(ENL_COMM_ALLOW)
E7X_COMM(ENL_COMM_ENABLE)
E7X_COMM(ENL_COMM_CLEAR)
E7X_COMM(ENL_COMM_QUERY)
E7X_COMM(ENL_COMM_EVENT)
E7X_COMM(ENL_COMM_SET)
E7X_COMM(ENL_COMM_GET)

E7X_ATTR(ENL_ATTR_NESTED, NLA_NESTED)
E7X_ATTR(ENL_ATTR_PATH, NLA_NUL_STRING)
E7X_ATTR(ENL_ATTR_FLAG, NLA_U32)
E7X_ATTR(ENL_ATTR_PROT, NLA_U32)
E7X_ATTR(ENL_ATTR_STATE, NLA_U32)
E7X_ATTR(ENL_ATTR_VALUE, NLA_U32)
