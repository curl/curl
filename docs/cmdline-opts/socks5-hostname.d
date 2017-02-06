Long: socks5-hostname
Arg: <host[:port]>
Help: SOCKS5 proxy, pass host name to proxy
Added: 7.18.0
---
Use the specified SOCKS5 proxy (and let the proxy resolve the host name). If
the port number is not specified, it is assumed at port 1080.

Since 7.21.7, this option is superfluous since you can specify a socks5
hostname proxy with --proxy using a socks5h:// protocol prefix.

This option typically overrides any previous use of --proxy; however since
7.52.0 if --proxy is used to specify an HTTP or HTTPS proxy then curl will
attempt to use it with the SOCKS proxy. In such a case curl first connects to
the SOCKS proxy and then connects (through SOCKS) to the HTTP or HTTPS proxy.

If this option is used several times, the last one will be used.
