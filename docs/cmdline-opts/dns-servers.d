c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dns-servers
Arg: <addresses>
Help: DNS server addrs to use
Requires: c-ares
Added: 7.33.0
Category: dns
Example: --dns-servers 192.168.0.1,192.168.0.2 $URL
See-also: dns-interface dns-ipv4-addr
---
Set the list of DNS servers to be used instead of the system default.
The list of IP addresses should be separated with commas. Port numbers
may also optionally be given as *:<port-number>* after each IP
address.

If this option is used several times, the last one will be used.
