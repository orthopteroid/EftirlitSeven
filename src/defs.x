E7X_NAME(eftirlit)
E7X_VERSION(1)

// * main firewall state commands
// DISCONNECT - lkm shutting down
//
// * rule management commands
// BLOCK [ PROT ] [ PATH ] - with no args is a command alias for 'set mode block'
// ALLOW [ PROT ] [ PATH ] - with no args is a command alias for 'set mode disabled'
// ENABLE - a command alias for 'set mode enabled'
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
// NB: aliases are identifiers used in the daemon ui to represent
// a uint32 value for the LKM.
//
// PATH - a string, always starting with / and in the case of a folder, ending with /
// PROT - can be an alias from the constant table or a uint
// STATE - any of E7C_BLOCK, E7C_ALLOW, E7C_PENDING*  (*unimplemented)
// NESTED - netlink grammar sugar (internal attribute)
// action flags should either be allow or block (E7C_ALLOW, E7C_BLOCK)
// boolean flags should be either disabled or enabled (E7C_DISABLED, E7C_ENABLED)
// numeric flags should be a uint but an alias from the constant table can be specified

// ID, e7d alias and constant value
E7X_CONST(E7C_IP_ICMP,  "icmp",     IPPROTO_ICMP)
E7X_CONST(E7C_IP_TCP,   "tcp",      IPPROTO_TCP)
E7X_CONST(E7C_IP_UDP,   "udp",      IPPROTO_UDP)
E7X_CONST(E7C_IP_ANY,   "any",      ~0)
E7X_CONST(E7C_BLOCK,    "block",    0xFF00)
E7X_CONST(E7C_ALLOW,    "allow",    0xFF01)
E7X_CONST(E7C_PENDING,  "pending",  0xFF02)
E7X_CONST(E7C_ENABLED,  "enabled",  0xFF03)
E7X_CONST(E7C_DISABLED, "disabled", 0xFF04)

// ID, e7d alias and default LKM value
E7X_FLAG(E7F_MODE,                 "mode",    E7C_DISABLED)  // E7C_ENABLED, E7C_DISABLED, E7C_BLOCK
E7X_FLAG(E7F_DEBUG,                "debug",   E7C_ENABLED)
E7X_FLAG(E7F_FAILPATH_ACTION,      "fail",    E7C_ALLOW)
E7X_FLAG(E7F_UNKN_PROCESS_ACTION,  "unkproc", E7C_ALLOW)
E7X_FLAG(E7F_UNKN_PROTOCOL_ACTION, "unkprot", E7C_ALLOW)
E7X_FLAG(E7F_NORULE_NOTIFY,        "norule",  E7C_ENABLED)   // notify daemon of packets that have no rule
E7X_FLAG(E7F_NORULE_SQUELCH,       "squelch", E7C_ENABLED)   // squelch between E7F_NORULE_NOTIFY for each (proto,path) pair
E7X_FLAG(E7F_NORULE_ACTION,        "unkrule", E7C_ALLOW)     // what to do with a packet that has no rule (ACCEPT) todo: QUEUE
E7X_FLAG(E7F_RULE_DROPS,           "drops",   E7C_DISABLED)  // notify daemon when a packet is DROPPED due to a rule
E7X_FLAG(E7F_RULE_ACCEPTS,         "accepts", E7C_DISABLED)  // notify daemon when a packet is ACCEPTED due to a rule
E7X_FLAG(E7F_RULE_CHANGE_QUERY,    "rchngq",  E7C_ENABLED)   // notify daemon with full query when rules are added/removed
E7X_FLAG(E7F_STAT_UPTIME,          "uptime",  0) // in secs. psuedoflag. initialized on module start
E7X_FLAG(E7F_STAT_PACKETS,         "qpackets", 0)

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
