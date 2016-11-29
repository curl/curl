Long: socks4
Arg: <host[:port]>
Help: SOCKS4 proxy on given host + port
Added: 7.15.2
---
Use the specified SOCKS4 proxy. If the port number is not specified, it is
assumed at port 1080.

This option overrides any previous use of --proxy, as they are mutually
exclusive.

Since 7.21.7, this option is superfluous since you can specify a socks4 proxy
with --proxy using a socks4:// protocol prefix.

If this option is used several times, the last one will be used.
