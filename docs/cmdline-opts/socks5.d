c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: socks5
Arg: <host[:port]>
Help: SOCKS5 proxy on given host + port
Added: 7.18.0
Category: proxy
Example: --socks5 proxy.example:7000 $URL
See-also: socks5-hostname socks4a
Multi: single
---
Use the specified SOCKS5 proxy - but resolve the host name locally. If the
port number is not specified, it is assumed at port 1080.

To specify proxy on a unix domain socket, use localhost for host, e.g.
socks5://localhost/path/to/socket.sock

This option overrides any previous use of --proxy, as they are mutually
exclusive.

This option is superfluous since you can specify a socks5 proxy with --proxy
using a socks5:// protocol prefix. (Added in 7.21.7)

Since 7.52.0, --preproxy can be used to specify a SOCKS proxy at the same time
--proxy is used with an HTTP/HTTPS proxy. In such a case curl first connects to
the SOCKS proxy and then connects (through SOCKS) to the HTTP or HTTPS proxy.

This option (as well as --socks4) does not work with IPV6, FTPS or LDAP.
