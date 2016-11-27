Long: socks4a
Arg: <host[:port]>
Help: SOCKS4a proxy on given host + port
Added: 7.18.0
---
Use the specified SOCKS4a proxy. If the port number is not specified, it is
assumed at port 1080.

This option overrides any previous use of --proxy, as they are mutually
exclusive.

Since 7.21.7, this option is superfluous since you can specify a socks4a proxy
with --proxy using a socks4a:// protocol prefix.

If this option is used several times, the last one will be used.
