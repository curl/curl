---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ip-tos
Arg: <string>
Help: Set IP Type of Service or Traffic Class
Added: 8.9.0
Category: connection
Protocols: All
Multi: single
See-also:
  - tcp-nodelay
  - vlan-priority
Example:
  - --ip-tos CS5 $URL
---

# `--ip-tos`

Set Type of Service (TOS) for IPv4 or Traffic Class for IPv6.

The values allowed for \<string\> can be a numeric value between 1 and 255
or one of the following:

CS0, CS1, CS2, CS3, CS4, CS5, CS6, CS7, AF11, AF12, AF13, AF21, AF22, AF23,
AF31, AF32, AF33, AF41, AF42, AF43, EF, VOICE-ADMIT, ECT1, ECT0, CE, LE,
LOWCOST, LOWDELAY, THROUGHPUT, RELIABILITY, MINCOST
