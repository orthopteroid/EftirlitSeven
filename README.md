*CONSIDER THIS BETA SOFTWARE - COMPILE AND USE AT YOUR OWN RISK*

# EftirlitSeven

E7 is a fork of the linux internet application firewall douane from https://gitlab.com/douaneapp with experimental changes. Some of the changes include...

## Known Socket Cache (ksc_ code prefix)

In douane, a list of socket identifiers for active connections are kept in a linked rcu list of structures, this facilitates the needs of lots of readers while writer needs are taken care of through the traditional spinlock and rculock mechanism. This cache is basically a list-of-structs - ie. a list of `struct process_socket_inode` items with each struct holding `fields` for socket-fd, inode, pid and name for each cached process.

In e7 I've tried to speed up searching by making better use of the processor cache by using an array-of-fields organization and associated array-search loops. I'm assuming that the arrays are small enough to fit into a processor's data cache and given the bus-width of the cpu-memory channel can be transferred efficiently to show some significant speed gains. Hopefully not too much to assume.

I've also tried to ensure that the cache will work on smp (where each core may have its own cache and that updates to one cache and eventually gets mirrored into other caches) by making cache updates serialized through a work queue of `struct change_work`. Giving this work queue affinity to a particular core/processor may be important to making this strategy work, additional testing and instrumentation needs to be done to determine this.

Cache entries have additional bookeeping that marks their age so least recently used entries can be overwritten. New cache entries or entries that see updates are marked using an atomic counter which is updated for each new cache entry. Slots for new entries are selected from the oldest slot using wrap-safe arithmetic on slot age.

## Active Socket Cache (asc_ code prefix)

In douane, when the pid of a socket-packet can't be identified from the cache of known sockets it engages in a search of the linux process table. It uses some kernel and distribution-based heuristics to speed the search but it is still just bruteforce.

In e7 I cache the results of this search in a hashtable, keyed on the socket inode which is directly available from the netfilter packet. This can result in some significant performance gains on my low-end testing hardware: 8us vs 800us. This cache is refreshed, as a block, when there is a cache-miss which only seems to occur for new socket-pid configurations.

## Submodules for INet protocols

In douane, the tcp and udp codepaths were one and the same with the protol's differing requirements for socket and process identification codepaths mainly the same and all located in the same netfilter handler.

E7 is adpoting the design of having submodules for each of the inet protocols, with their own protocol-hint parsing and process identification codepaths as well as their own separate init and exit routines to manage protocol specific resources. In addition to uncluttering the codepaths of some protocols with others it also facilitates a distributed development effort by simplifying merge and rebase workflows.

## Migrate from priviliged-netlink to generic-netlink

Allow unpriv access

## Console daemon

A simple daemon

## Stats tracker

Process, protocol, user, destination stats

## Typical log output

For typical log output on a low-end machine (around the time of commit ab016a2439e9b96b335fbaf1124f9f08164f25fc), see the file typical-log-output.txt

# Provenance

E7 is a fork of the linux internet application firewall douane from https://gitlab.com/douaneapp (where I've been volunteering during early 2021). Douane contains lots of great logic and infrastructure that can be leveraged to learn and experiment, as I have at https://gitlab.com/Orthopteroid/douane-dkms/ where I was testing smp-friendly cache-experiments. I've relocated those experiments to have most of my work under one roof here at github.

All core douane-originating logic and types are located in `douane.c` and where annotated in additional files. The code factoring necessary to make douane's core logic into a subcomponent has been conducted to help ensure compliance of douane's gpl based license: structs, types and functions that owe their heritage to douane are prefixed `douane_`. I have no desire to misrepresent the hard work of any authors of the material I'm relying upon here as my own work for this project.
