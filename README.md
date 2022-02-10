*THIS KERNEL MODULE SHOULD BE CONSIDERED BARELY BETA - COMPILE AND USE AT YOUR OWN RISK*

Development Details:
- kernel 5.4.0-74 (ubuntu 18.04.1 x64) on a friendly old ssd-assisted Intel Atom 330 (dual cpu with HT)
- libnl 3.2.29+ is needed to accommodate problems with attribute nesting
- `sudo make` will build the LKM on unsecure kernels
- `sudo make dkms` builds the LKM on secure kernels but if debugfs support is missing kernel log output is limited
- `sudo ./test` or `sudo ./test-dkms` will launch LKM for a test run. NB: these commands clobber your kernel.log
- `make_e7d` builds the C++ daemon which can be run with `sudo ./e7d`
- additional component debugging supported. `grep "define DEBUG_" src/*.c` for details.
- douaneapp source attributions included. `grep "douane" src/*` for details.
- reliance on crc32 in the LKM (for hashing filenames) and in the daemon (for hashing commands and constant-aliases in the control grammar).

# EftirlitSeven

E7 was originally a fork of douane (https://gitlab.com/douaneapp) with experimental changes. Some of the features in E7 include...

## Known Socket Cache (ksc_ code prefix)

E7 does lookups on known-sockets using a fixed-size cache-friendly memory organization. Sockets are hash-indexed by inode and writes are serialized using a work queue to be hopefully more SMP friendly (although switching to use the rcu subsystem might work better). LRU cache-entry bookeeping is done with a wrap-safe age calculation. Additional testing and instrumentation needs to be done to determine if this works properly.

## Active Socket Cache (asc_ code prefix)

When a search of the known-socket-cache fails, E7 does another inode hash-lookup for the socket in a secondary fixed-size cache. This cache is filled from the active sockets in the process table when a search here fails. So far, this cache appears to provide 10x to 100x lookup improvement during connection-storms. Additional investigations into how to use this cache effectively will continue.

## Rule Lookup Table (rule_ code prefix)

E7 uses another data structure for rules that determine if a (process,protocol) tuple can use the network interface. File hashes are used here prior to strncpy comparison for faster comparison. These rules are stored in a fixed-size circular queue to facilitate fast lookup and easy addition and removal but for very large rulesets something other than linear searching might need to be investigated. This queue is protected using a qrwlock, a type of spinlock that gives preference to updating the table over reading from it.

## Submodules for iNet protocols (prot_ file prefix)

E7 has submodules for each of the inet protocols, with their own protocol-hint parsing and process identification codepaths as well as their own separate init and exit routines to manage protocol specific resources. This has significantly uncluttered codepaths in the netfilter handler.

## Generic-Netlink (def_ code prefix)

E7 uses generic netlink and the attendant command, attribute and policy enumeration machinery to define the communications schema. Benefits of using a generic netlink system and schema include typed attributes, and command privilege levels. The netlink enumerations and structs are configured from a single x-macro file defs.x which initializes defs.h and defs.c for use by both the kernel module and the daemon. Using the x-macro file helps keep all netlink-related state synchronized between the .h and the .c for bothe the LKM and the daemon.

Userspace-bound netlink packets are transmitted asynchronously from a work-queue to prevent blocking of netfliter-callbacks that occur in softirq contexts - as it seems that netlink might block waiting for userspace to empty the socket buffer and blocking in a softirq is a no-no. Proto-E7 solutions were userspace related (secondary thread or resize via setsockopt) but E7 is trying to approach this problem on the LKM side - unstable userspace code should not make the kernel unstable.

## Single file Control Daemon (e7d)

The control daemon in E7 is a console app with streamlined use of epoll to handle singals, netlink and stdin commands. The daemon also uses some command-string parsing tricks (C++ constexpr string hash calculation) that hopefully aren't too clever.

## Firewall State Control (defs.x)

In addition to E7's netlink schema in `defs.x` this file also contains identifiers and aliases for all of the firewall's internal state and the netlink-specific management commands to manipulate this state. All this information is shared by the LKM and the daemon in various amounts - but the goal in having it all in `defs.x` is to keep it all synchronized. Briefly, here are the main parts of the grammar:
- constants: their identifiers, text aliases and specific values
- flags: their identifiers, text aliases and default constant value
- commands: netlink packet commands
- attributes: netlink packet attributes and their datatypes

`defs.x` is also commented to indicate how the netlink command grammar and the use of the flags and constants all fit together. For more information see `e7d.c` and `netlink.c` for how these packets are sent and received.

Launching `./e7d` will launch the interactive control daemon. Commands that take constant or flag parameters can use numeric values or the alias (per the defs.x file). The aliases are only used in the daemon to help in communicating with the LKM - the daemon uses a simple syntax to convert the aliases into the numerical constants that are sent over netlink to the LKM. Examples are:
```
allow udp /bin/ping
allow tcp /bin/netcat
allow tcp /usr/bin/socat
clear tcp /usr/bin/socat
allow /usr/lib/firefox/firefox
clear allow
block udp /usr/bin/socat
clear block
set mode disable
get mode
query
query allow
query block
quit
disconnect
```

Partial protocol and path matches (both experimental!) are supported with the `any` psuedo-protocol or with a trailing / in the path. like:
```
allow any /bin/
block tcp /usr/bin/
```

Of course, all the actual constants for interacting with the LKM are also in the defs.x file and could be used by any other daemon implementation without needing the aliases.
  
## LKM log output

For typical LKM log output on a low-end machine (around the time of commit ab016a2439e9b96b335fbaf1124f9f08164f25fc), see the file typical-log-output.txt

## Future Work

Monitoring or stats tracking for other parameters, including specific process-instances, users or destinations. Additionally, it would be useful to take kernel parmaters for the module so module flags can be manipulated at boot-time to prevent packet leakage.

# Security Considerations

- The LKM uses netlink to allow non-root connections to query the firewall state, but not change any of the firewall state.
- Only filenames are in the ruleset, not hashes of the files themselves.

# Provenance

E7 is an extensive fork of the linux internet application firewall douane from https://gitlab.com/douaneapp (I was a contributor in early 2021). Douane contains lots of great logic and infrastructure that can be leveraged to learn and experiment, as I have at https://gitlab.com/Orthopteroid/douane-dkms/ where I was testing smp-friendly cache-experiments. I've relocated those experiments to have most of my work under one roof here at github. I've tried to properly give credit to douane with grep-friendly code annotations to help ensure compliance of douane's gpl based license. It is not my intention to misrepresent the hard work of any authors of douane as my own work for this project.
