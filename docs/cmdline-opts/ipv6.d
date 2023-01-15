c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: 6
Long: ipv6
Tags: Versions
Protocols:
Added: 7.10.8
Mutexed: ipv4
Requires:
See-also: http1.1 http2
Help: Resolve names to IPv6 addresses
Category: connection dns
Example: --ipv6 $URL
Multi: boolean
---
This option tells curl to use IPv6 addresses only, and not for example try
IPv4.
