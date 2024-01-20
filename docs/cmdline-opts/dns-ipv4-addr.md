---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dns-ipv4-addr
Arg: <address>
Help: IPv4 address to use for DNS requests
Protocols: DNS
Added: 7.33.0
Requires: c-ares
Category: dns
Multi: single
See-also:
  - dns-interface
  - dns-ipv6-addr
Example:
  - --dns-ipv4-addr 10.1.2.3 $URL
---

# `--dns-ipv4-addr`

Tell curl to bind to a specific IP address when making IPv4 DNS requests, so
that the DNS requests originate from this address. The argument should be a
single IPv4 address.
