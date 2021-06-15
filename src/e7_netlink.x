// <created> = auto | manual
// <state> = enable | disable
// <criteria> = [process] [protocol] [device] [user] [group]
// <action> = (allow | block) [log | nolog]
// LOG u->m = <state> | query
// LOG u<-m = <state>
// MODE u->m = <state> | query | hello | bye
// MODE u<-m = <state> | bye
// RULE u->m = ( <criteria> | <cxtid> ) <action> [<state> | remove]
// RULES u->m = query | clear
// RULES u<-m = <criteria> <cxtid> <created> <action> <state>
// EVENT u<-m = <criteria> <cxtid> [query]

E7X_NAME(eftirlit)
E7X_VERSION(1)

E7X_COMM(ENL_COMM_ECHO) // removeme: old demo code
E7X_COMM(ENL_COMM_LOG)
E7X_COMM(ENL_COMM_MODE)
E7X_COMM(ENL_COMM_RULE)
E7X_COMM(ENL_COMM_RULES)
E7X_COMM(ENL_COMM_EVENT)

E7X_ATTR(ENL_ATTR_ECHOBODY, NLA_NUL_STRING) // removeme: old demo code
E7X_ATTR(ENL_ATTR_ECHONESTED, NLA_NESTED) // removeme: old demo code
E7X_ATTR(ENL_ATTR_RULENESTED, NLA_NESTED)

// <state>
E7X_ATTR(ENL_ATTR_ENABLE, NLA_FLAG)
E7X_ATTR(ENL_ATTR_DISABLE, NLA_FLAG)
E7X_ATTR(ENL_ATTR_AUTO, NLA_FLAG)
E7X_ATTR(ENL_ATTR_MANUAL, NLA_FLAG)

// <criteria>
E7X_ATTR(ENL_ATTR_CONTEXT_ID, NLA_U32)
E7X_ATTR(ENL_ATTR_PROCESS_ID, NLA_U32)
E7X_ATTR(ENL_ATTR_PROTOCOL_ID, NLA_U32)
E7X_ATTR(ENL_ATTR_USER_ID, NLA_U32)
E7X_ATTR(ENL_ATTR_GROUP_ID, NLA_U32)
E7X_ATTR(ENL_ATTR_PROCESS_STR, NLA_NUL_STRING)
E7X_ATTR(ENL_ATTR_DEVICE_STR, NLA_NUL_STRING)

// <action>
E7X_ATTR(ENL_ATTR_ALLOW, NLA_FLAG)
E7X_ATTR(ENL_ATTR_BLOCK, NLA_FLAG)
E7X_ATTR(ENL_ATTR_LOG, NLA_FLAG)
E7X_ATTR(ENL_ATTR_NOLOG, NLA_FLAG)

// misc
E7X_ATTR(ENL_ATTR_REMOVE, NLA_FLAG)
E7X_ATTR(ENL_ATTR_QUERY, NLA_FLAG)
E7X_ATTR(ENL_ATTR_CLEAR, NLA_FLAG)
E7X_ATTR(ENL_ATTR_HELLO, NLA_FLAG)
E7X_ATTR(ENL_ATTR_BYE, NLA_FLAG)
