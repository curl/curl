---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dns-ipv6-addr
Arg: <address>
Help: IPv6 address to use for DNS requests
Protocols: DNS
Added: 7.33.0
Requires: c-ares
Category: dns
Multi: single
See-also:
  - dns-interface
  - dns-ipv4-addr
Example:
  - --dns-ipv6-addr 2a04:4e42::561 $URL
---

# `--dns-ipv6-addr`

Tell curl to bind to a specific IP address when making IPv6 DNS requests, so
that the DNS requests originate from this address. The argument should be a
single IPv6 address.
