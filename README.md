*THIS KERNEL MODULE SHOULD BE CONSIDERED BARELY BETA - COMPILE AND USE AT YOUR OWN RISK*

*May not even be safe inside a paravirtualized VM - still investigating*

Development Details:
- kernel 5.4.0-74 (ubuntu 18.04.1 x64) on a friendly old ssd-assisted Intel Atom 330 (dual cpu with HT)
- libnl 3.2.29+ is needed to accomodate problems with attribute nesting
- `make_e7d` builds the C++11 daemon, `make` will build the LKM on unsecure kernels
- `make dkms` builds the LKM on secure kernels but if debugfs support is missing kernel log output is limited
- launch LKM for a test run with `./test` or `./test-dkms`. NB: these commands clobber your kernel.log
- additional component debugging supported. `grep "define DEBUG_" src/*.c` for details.
- douaneapp source attributions included. `grep "douane" src/*` for details.

# EftirlitSeven

E7 was originally a fork of douane (https://gitlab.com/douaneapp) with experimental changes. Code has shifted quite a bit so it's not easy to find the origins. Use `grep` to find attributions to douane code and algorithims. Some of the features in E7 include...

## Known Socket Cache (ksc_ code prefix)

E7 tries to make searching for a previously seen socket fast by using an array-of-fields cache-friendly memory organization. This assumes that the arrays are small enough to fit into a processor's data cache and given the bus-width of the cpu-memory channel can be transferred efficiently to show some significant speed gains. Hopefully not too much to assume.

Another goal for E7 has been that this caching will work properly on SMP (were processor-cache peek, snoop or mirroring might not work as expected) by serializing cache updates through a kernel work queue. Atomic LRU bookeeping is used to identify old cache entries for overwrite using wrap-safe arithmetic on entry age. Giving the work queue affinity to a particular core/processor may be important to making this strategy work, additional testing and instrumentation needs to be done to determine this.

## Active Socket Cache (asc_ code prefix)

When a search of the known-socket-cache fails E7 searches another cache for the inode in the netfilter packet. This cache is made from the active sockets in the process table, and if a cache lookup fails the cache is regenerated. In testing so far, this cache appears to provide 10x to 100x lookup improvement during connection-storms. Additional investigations into how to use this cache effectively will continue.

## Submodules for iNet protocols (prot_ file prefix)

E7 has submodules for each of the inet protocols, with their own protocol-hint parsing and process identification codepaths as well as their own separate init and exit routines to manage protocol specific resources. This has significantly uncluttered codepaths in the netfilter handler.

## Generic-Netlink (def_ code prefix)

E7 uses generic netlink and the attendant command, attribute and policy enumeration machinery to define the communications schema. Benefits of using a generic netlink system and schema include typed attributes, and command privilege levels. The netlink enumerations and structs are configured from a single x-macro file defs.x which initializes defs.h and defs.c for use by both the kernel module and the daemon. Using the x-macro file helps keep all netlink-related state synchronized between the .h and the .c for bothe the LKM and the daemon.

Userspace-bound netlink packets are transmitted asynchronously from a work-queue to prevent blocking of netfliter-callbacks that occur in softirq contexts - as it seems that netlink might block waiting for userspace to empty the socket buffer and blocking in a softirq is a no-no. Proto-E7 solutions were userspace related (secondary thread or resize via setsockopt) but E7 is trying to approach this problem on the LKM side - unstable userspace code should not make the kernel unstable.

## Single file Control Daemon (e7d)

The control daemon in E7 is a console app with streamlined use of epoll to handle singals, netlink and stdin commands. The daemon also uses some command-string parsing tricks (C++11 constexpr string hash calculation) that hopefully aren't too clever.

## Firewall State Control (defs.x)

In addition to E7's netlink schema in `defs.x` this file also contains identifiers and aliases for all of the firewall's internal state and the netlink-specific management commands to manipulate this state. All this information is shared by the LKM and the daemon in various amounts - but the goal in having it all in `defs.x` is to keep it all synchronized. Briefly, here are the main parts of the grammar:
- constants: their identifiers, text aliases and specific values
- flags: their identifiers, text aliases and default constant value
- commands: netlink packet commands
- attributes: netlink packet attributes and their datatypes

`defs.x` is also commented to indicate how the netlink command grammar and the use of the flags and constants all fit together. For more information see `e7d.c` and `netlink.c` for how these packets are sent and received.

## Stats tracker

Future work: Process, protocol, user, destination stats

## LKM log output

For typical LKM log output on a low-end machine (around the time of commit ab016a2439e9b96b335fbaf1124f9f08164f25fc), see the file typical-log-output.txt

# Provenance

E7 is a fork of the linux internet application firewall douane from https://gitlab.com/douaneapp (I was a contributor in early 2021). Douane contains lots of great logic and infrastructure that can be leveraged to learn and experiment, as I have at https://gitlab.com/Orthopteroid/douane-dkms/ where I was testing smp-friendly cache-experiments. I've relocated those experiments to have most of my work under one roof here at github. I've tried to properly give credit a douane via grep-friendly code annotations to help ensure compliance of douane's gpl based license. It isnot my intention to misrepresent the hard work of any authors of douane as my own work for this project.
