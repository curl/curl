c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: 4
Long: ipv4
Tags: Versions
Protocols:
Added: 7.10.8
Mutexed: ipv6
Requires:
See-also: http1.1 http2
Help: Resolve names to IPv4 addresses
Category: connection dns
Example: --ipv4 $URL
Multi: mutex
---
This option tells curl to use IPv4 addresses only when resolving host names,
and not for example try IPv6.
