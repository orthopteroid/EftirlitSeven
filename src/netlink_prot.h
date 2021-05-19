#ifndef _NETLINK_PROT_H_
#define _NETLINK_PROT_H_

// eftirlit7 (gpl3) - orthopteroid@gmail.com
// forked from douane-lkms (gpl3) - zedtux@zedroot.org

/*

**DRAFT** 5Mar2021

The Application Fire Wall (AFW) kernel module is controlled via a netlink
connection to userland. This connection is performed using commands (marked below with *)
containing one or more attributes or attribute lists (as an aside netlink lists must be
built using recursion, so, the exact formulation of the below grammar reflects that).

First of all, as this is a spec for an AFW, considerations for the filtering of packet
requests on the basis of source or destination address is omitted. While the destination
address is provided back to userland this is merely done for information purposes - no
filtering provisions are supported on the basis of source or destination address.

However, as an "application firewall" being able to filter on any part of the application's
calling context, not just the process name. The full calling context could include the
process or connection device name or any of the numerical IDs for the process, the
protocol or user or group ids. It is with these contextual aspects of an application's
connection that this netlink communication grammar has been designed.

A handy feature of using netlink is the ability to mark commands as executable from
unpriv userland processes or not. In the case of a userland GUI that wishes to enumerate
the full state of the AFW and all the active rules this is ideal as it requires only
the code that needs to make AFW changes, at the time it needs to make those changes, drop
to root.

The control grammar for the LKM can be easily broken down into six sections, with each
building upon the earlier sections:

1. Events

Application communication attempts <event> are captured from netfilter and pull apart
to determine contextual information about the connection. This information <cxt> is not
limited to processName, processID, deviceName and user and group ids. The destination
address <dest> is also collected for convience purposes.

<cxt> = procName | procId | protocolId | deviceName | userId | groupId
<dest> = <text>
<event> = <cxt> <dest>

Using it's list of rules the AFW may choose to accept or reject the connection. If there
is no rule then the <event> may be passed to a daemon which might ask the user
to approve the connection.

2. Sinks

In order for the <event> to pass to userland a daemon must register itself as a <sink>
for <event> packets. It would be considered good practice if after enabling itself
as a sink it would disable itself prior to disconnection.

<eopt> = enable | disable
<sink*> = <eopt>

3. Removal of rules

Removal of AFW rules is straightforward using a 'remove' directive with one or more pieces
of context <cxt> information that determine the match <clist>. Multiple rules are removed
using a list <rlist>:

<clist> = <cxt> [ <clist> ]
<rlist> = remove <clist> [ <rlist> ]

4. Adding rules

Adding requires using the 'add' directive followed by a list of matching contexts <clist>, an
option <eopt> to add the rule enabled or not and a logging option <lopt> that will force
logging of this rule if it occurs subsequently. Adding rules to the AFW can similarly be
done either individually or using a list <alist>.

<lopt> = log | nolog
<alist> = add <clist> [ <eopt> ] [ <lopt> ] [ <alist> ]

5. Change AFW state

Changes to the AFW state come through the main command <change>. In addition to
using add and remove directives, the other directives that can optionally be used here include main
AFW control <eopt>, AFW logging <lopt> and AFW mode (ie blacklist or whitelist mode) <mopt>.

<mopt> = whitelist | blacklist
<change*> = [ <mopt> ] [ <eopt> ] [ <lopt> ] [ <rlist> ] [ <alist> ]

6. Rule query

The 'query' command returns the AFW mode <mopt>, if the AFW is enabled <eopt> and if logging
is enabled <lopt> and if any rules are currently loaded they are returned as a list <qlist>.
Each item in the list has a 'rule' directive, the matching context <clist> and designates if
the rule is active <eopt> andif logging is enabled <lopt>.

<qlist> = rule <clist> <eopt> [ <lopt> ] [ <qlist> ]
<query*> = <mopt> <eopt> <lopt> [ <qlist> ]

7.

Lastly, the simplest command <reset> makes the AFW return to it's default state.

<reset*> = <>

8. To sum up

There are just four high level 'commands' for the AFW. These correspond
to generic-netlink commands that can require different caller privs. For example, 'query'
can come from a non-root caller in order to build a gui while the others all require
root privs:

'sink' start / stop sending me <event> packets
'change' change things in the AFW state
'query' send me full AFW state
'reset' reset lkm state

*/


#endif // _NETLINK_PROT_H_
