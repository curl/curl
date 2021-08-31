Long: dns-interface
Arg: <interface>
Help: Interface to use for DNS requests
Protocols: DNS
See-also: dns-ipv4-addr dns-ipv6-addr
Added: 7.33.0
Requires: c-ares
Category: dns
Example: --dns-interface eth0 $URL
---
Tell curl to send outgoing DNS requests through <interface>. This option is a
counterpart to --interface (which does not affect DNS). The supplied string
must be an interface name (not an address).
