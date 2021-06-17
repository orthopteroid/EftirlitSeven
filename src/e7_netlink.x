E7X_NAME(eftirlit)
E7X_VERSION(1)

// The goal here is to trade off more command for fewer attributes
// so that less space is wasted during transmission of a nested
// query result.
//
// basic attribs:
// NESTED
// FLAG flagname
// PATH processpath
// PROT protocol = uint32
// STATE statevalue = ERROR, BLOCK, ALLOW, PENDING, ENABLED, DISABLED, LOCKDOWN
// VALUE flagvalue = uint32
//
// * main firewall state commands
// DISCONNECT - lkm shutting down
//
// * rule management commands
// BLOCK [ PROT | PATH ]
// ALLOW [ PROT | PATH ]
// QUERY [ STATE ] - returns QUERY STATE [ PROT ] [ PATH ] [ NESTED ]
//
// * outbound connection attempts that require auth
// EVENT PROT PATH STATE
//
// * internal flag management commands
// SET FLAG VALUE
// GET FLAG - returns GET FLAG VALUE
//

E7X_CONST(ENL_CONST_BLOCK) // aka: NF_DROP
E7X_CONST(ENL_CONST_ALLOW) // aka: NF_ACCEPT
E7X_CONST(ENL_CONST_PENDING)
E7X_CONST(ENL_CONST_ENABLED)
E7X_CONST(ENL_CONST_DISABLED)
E7X_CONST(ENL_CONST_LOCKDOWN)
E7X_CONST(ENL_CONST_ERROR)
E7X_CONST(ENL_CONST_PASSTHROUGH) // > NF_STOP (5)

E7X_FLAG(E7F_MODE, ENL_CONST_PROCESS)               // block, allow or passthrough
E7X_FLAG(E7F_DEBUG, 1)
E7X_FLAG(E7F_FAILPATH_ACTION, ENL_CONST_ALLOW)
E7X_FLAG(E7F_UNKN_PROCESS_ACTION, ENL_CONST_ALLOW)
E7X_FLAG(E7F_UNKN_PROTOCOL_ACTION, ENL_CONST_ALLOW)
E7X_FLAG(E7F_RULE_QUERY_EVENTS, 1)                   // notify daemon of packets that have no rule (usually 1)
E7X_FLAG(E7F_RULE_QUERY_ACTION, ENL_CONST_ALLOW)     // what to do with a packet that has no rule (ACCEPT) todo: QUEUE
E7X_FLAG(E7F_RULE_DROP_EVENTS, 0)                    // notify daemon when a packet is DROPPED due to a rule (usually 0)
E7X_FLAG(E7F_RULE_ACCEPT_EVENTS, 0)                  // notify daemon when a packet is ACCEPTED due to a rule (usually 0)

E7X_COMM(ENL_COMM_DISCONNECT)
E7X_COMM(ENL_COMM_BLOCK)
E7X_COMM(ENL_COMM_UNBLOCK)
E7X_COMM(ENL_COMM_QUERY)
E7X_COMM(ENL_COMM_EVENT)
E7X_COMM(ENL_COMM_SET)
E7X_COMM(ENL_COMM_GET)

E7X_ATTR(ENL_ATTR_NESTED, NLA_NESTED)
E7X_ATTR(ENL_ATTR_PATH, NLA_NUL_STRING)
E7X_ATTR(ENL_ATTR_PROT, NLA_U32)
E7X_ATTR(ENL_ATTR_STATE, NLA_U32)
E7X_ATTR(ENL_ATTR_VALUE, NLA_U32)
