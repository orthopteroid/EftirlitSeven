*THIS KERNEL MODULE SHOULD BE CONSIDERED BARELY BETA - COMPILE AND USE AT YOUR OWN RISK*

Development Details:
- kernel 5.4.0-74 (ubuntu 18.04.1 x64)
- old Intel Atom 330 with a nice SSD
- libnl 3.2.29+ is needed to accomodate problems with attribute nesting
- `make_e7d` builds the C++11 daemon, `make` will build the LKM on unsecure kernels
- `make dkms` builds the LKM on secure kernels but if debugfs support is missing kernel log output is limited
- launch LKM for a test run with `./test` or `./test-dkms`. NB: these command clobber your kernel.log
- additional component debugging supported. `grep "define DEBUG_" src/*.c` for details.

# EftirlitSeven

E7 is a fork of the linux internet application firewall douane from https://gitlab.com/douaneapp with experimental changes. Some of the changes include...

## Known Socket Cache (ksc_ code prefix)

In douane, a list of socket identifiers for active connections are kept in a linked rcu list of structures, this facilitates the needs of lots of readers while writer needs are taken care of through the traditional spinlock and rculock mechanism. This cache is basically a list-of-structs - ie. a list of `struct process_socket_inode` items with each struct holding `fields` for socket-fd, inode, pid and name for each cached process.

E7 tries to speed up searching by making better use of the processor cache by using an array-of-fields organization and associated array-search loops. This assumes that the arrays are small enough to fit into a processor's data cache and given the bus-width of the cpu-memory channel can be transferred efficiently to show some significant speed gains. Hopefully not too much to assume.

Another goal for E7 is that this caching will work properly on SMP (were processor-cache peek, snoop or mirroring might not work as expected) by serializing cache updates through a kernel work queue. Atomic LRU bookeeping is used to identify old cache entries for overwrite using wrap-safe arithmetic on entry age. Giving the work queue affinity to a particular core/processor may be important to making this strategy work, additional testing and instrumentation needs to be done to determine this.

## Active Socket Cache (asc_ code prefix)

In douane, when the pid of a socket-packet can't be identified from the cache of known sockets it engages in a search of the linux process table. It uses some kernel and distribution-based heuristics to speed the search but it is still just bruteforce.

E7 caches the results of this search in a hashtable, keyed on the socket inode which is directly available from the netfilter packet. This can result in some significant performance gains on my low-end testing hardware: 8us vs 800us. This cache is refreshed, as a block, when there is a cache-miss which only seems to occur for new socket-pid configurations. Additional investigations into how to use this cache effectively will continue.

## Submodules for iNet protocols

In douane, the tcp and udp codepaths were one and the same with the differing protol requirements for socket and process identification handled mainly on the same codepath and located in the same netfilter handler.

E7 is adpoting the design of having submodules for each of the inet protocols, with their own protocol-hint parsing and process identification codepaths as well as their own separate init and exit routines to manage protocol specific resources. In addition to uncluttering the codepaths of some protocols with others it also facilitates a distributed development effort by simplifying merge and rebase workflows if those parsers were to continue to be worked on.

## Migrate from priviliged-netlink to generic-netlink

Douane has been written initally to use basic netlink with a binary struct to communicate with kernelspace.

E7 uses generic netlink and the attendant command, attribute and policy enumeration machinery to define the communications schema. Benefits of using a generic netlink system and schema include typed attributes, command privilege levels and multicast subscribers.

E7 also uses X-Macro tricks to place all generic netlink protocol particulars into the single file E7_netlink.x so it stays synchronized between the LKM and the daemon.

## Console daemon

In E7 the control daemon is a console app with streamlined use of epoll to handle singals, netlink and stdin commands. The daemon also uses some command-string parsing tricks (C++11 constexpr string hash calculation) that hopefully aren't too clever.

## Stats tracker

Future work: Process, protocol, user, destination stats

## LKM log output

For typical LKM log output on a low-end machine (around the time of commit ab016a2439e9b96b335fbaf1124f9f08164f25fc), see the file typical-log-output.txt

# Provenance

E7 is a fork of the linux internet application firewall douane from https://gitlab.com/douaneapp (where I've been volunteering during early 2021). Douane contains lots of great logic and infrastructure that can be leveraged to learn and experiment, as I have at https://gitlab.com/Orthopteroid/douane-dkms/ where I was testing smp-friendly cache-experiments. I've relocated those experiments to have most of my work under one roof here at github.

All core douane-originating logic and types are located in `douane.c` and where annotated in additional files. The code factoring necessary to make douane's core logic into a subcomponent has been conducted to help ensure compliance of douane's gpl based license: structs, types and functions that owe their heritage to douane are prefixed `douane_`. I have no desire to misrepresent the hard work of any authors of the material I'm relying upon here as my own work for this project.
