# EftirlitSeven

E7 is a fork of the linux internet application firewall douane from https://gitlab.com/douaneapp (where I've been volunteering during early 2021). Specifically, it comes from https://gitlab.com/Orthopteroid/douane-dkms/-/tree/pamplemousse where I was testing smp-friendly cache-experiments. I've relocated those experiments to have most of my work under one roof here at github.

Douane itself contains lots of great logic and infrastructure that I've leveraged in order to add a different backend caching algorithim (that hopefully works?). Other changes I hope to eventually include, in no particular order, are...
- a similar type of cacheing for rules as I've added for process-names
- a netlink api that uses generic netlink multiplexing
- user-based rules
- protocol-based rules
- a simple console daemon

# Provenance

All core douane-originating logic and types are located in `douane.c` and `douane_types.h`. The code factoring necessary to make douane's core logic into a subcomponent has been conducted to help ensure compliance of douane's gpl based license: structs, types and functions that owe their heritage to douane are prefixed `douane_`. I have no desire to misrepresent the hard work of any authors of the material I'm relying upon here as my own work for this project.
