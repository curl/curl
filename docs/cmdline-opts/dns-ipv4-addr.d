Long: dns-ipv4-addr
Arg: <address>
Help: IPv4 address to use for DNS requests
Protocols: DNS
See-also: dns-interface dns-ipv6-addr
Added: 7.33.0
Requires: c-ares
Category: dns
---
Tell curl to bind to <ip-address> when making IPv4 DNS requests, so that
the DNS requests originate from this address. The argument should be a
single IPv4 address.
