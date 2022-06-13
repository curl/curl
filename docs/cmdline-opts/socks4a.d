c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: socks4a
Arg: <host[:port]>
Help: SOCKS4a proxy on given host + port
Added: 7.18.0
Category: proxy
Example: --socks4a hostname:4096 $URL
See-also: socks4 socks5 socks5-hostname
---
Use the specified SOCKS4a proxy. If the port number is not specified, it is
assumed at port 1080. This asks the proxy to resolve the host name.

To specify proxy on a unix domain socket, use localhost for host, e.g.
socks4a://localhost/path/to/socket.sock

This option overrides any previous use of --proxy, as they are mutually
exclusive.

This option is superfluous since you can specify a socks4a proxy with --proxy
using a socks4a:// protocol prefix. (Added in 7.21.7)

Since 7.52.0, --preproxy can be used to specify a SOCKS proxy at the same time
--proxy is used with an HTTP/HTTPS proxy. In such a case curl first connects to
the SOCKS proxy and then connects (through SOCKS) to the HTTP or HTTPS proxy.

If this option is used several times, the last one will be used.
