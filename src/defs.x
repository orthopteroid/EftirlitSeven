E7X_NAME(eftirlit)
E7X_VERSION(1)

// basic attribs:
// NESTED
// string: PATH
// E7F_ values: FLAG
// E7C_ subset: STATE
// uint32: PROT, VALUE
//
// * main firewall state commands
// DISCONNECT - lkm shutting down
//
// * rule management commands
// BLOCK [ PROT | PATH ]
// ALLOW [ PROT | PATH ]
// QUERY [ STATE ] - returns QUERY STATE [ PROT ] [ PATH ] [ NESTED ]
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
// b = boolean (E7C_DISABLED, E7C_ENABLED)
// c = constant (their own value)
// e = enumerated (E7C_DISABLED, E7C_ENABLED, E7C_LOCKDOWN)

// ID and e7d alias
E7X_CONST(E7C_BLOCK,    "cblock")
E7X_CONST(E7C_ALLOW,    "callow")
E7X_CONST(E7C_PENDING,  "cpending")
E7X_CONST(E7C_ENABLED,  "cenabled")
E7X_CONST(E7C_DISABLED, "cdisabled")
E7X_CONST(E7C_LOCKDOWN, "clockdown")

// ID, e7d alias and default LKM value
E7X_FLAG(E7F_MODE,                 "emode", E7C_DISABLED)        // enabled, disabled, lockdown
E7X_FLAG(E7F_DEBUG,                "bdebug", E7C_ENABLED)
E7X_FLAG(E7F_FAILPATH_ACTION,      "afail", E7C_ALLOW)
E7X_FLAG(E7F_UNKN_PROCESS_ACTION,  "aunkproc", E7C_ALLOW)
E7X_FLAG(E7F_UNKN_PROTOCOL_ACTION, "aunkprot", E7C_ALLOW)
E7X_FLAG(E7F_RULE_QUERY_EVENTS,    "bnotifynorule", E7C_ENABLED)    // notify daemon of packets that have no rule
E7X_FLAG(E7F_RULE_QUERY_ACTION,    "aunkrule", E7C_ALLOW)           // what to do with a packet that has no rule (ACCEPT) todo: QUEUE
E7X_FLAG(E7F_RULE_DROP_EVENTS,     "bnotifydrops", E7C_DISABLED)    // notify daemon when a packet is DROPPED due to a rule
E7X_FLAG(E7F_RULE_ACCEPT_EVENTS,   "bnotifyaccepts", E7C_DISABLED)  // notify daemon when a packet is ACCEPTED due to a rule

E7X_COMM(ENL_COMM_ERROR)
E7X_COMM(ENL_COMM_DISCONNECT)
E7X_COMM(ENL_COMM_BLOCK)
E7X_COMM(ENL_COMM_UNBLOCK)
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
