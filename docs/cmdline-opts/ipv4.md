---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: 4
Long: ipv4
Tags: Versions
Protocols:
Added: 7.10.8
Mutexed: ipv6
Requires:
Help: Resolve names to IPv4 addresses
Category: connection dns
Multi: mutex
See-also:
  - http1.1
  - http2
Example:
  - --ipv4 $URL
---

# `--ipv4`

Use IPv4 addresses only when resolving hostnames, and not for example try
IPv6.
