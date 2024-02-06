---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: socks5-hostname
Arg: <host[:port]>
Help: SOCKS5 proxy, pass host name to proxy
Added: 7.18.0
Category: proxy
Multi: single
See-also:
  - socks5
  - socks4a
Example:
  - --socks5-hostname proxy.example:7000 $URL
---

# `--socks5-hostname`

Use the specified SOCKS5 proxy (and let the proxy resolve the host name). If
the port number is not specified, it is assumed at port 1080.

To specify proxy on a unix domain socket, use localhost for host, e.g.
`socks5h://localhost/path/to/socket.sock`

This option overrides any previous use of --proxy, as they are mutually
exclusive.

This option is superfluous since you can specify a socks5 hostname proxy with
--proxy using a socks5h:// protocol prefix. (Added in 7.21.7)

--preproxy can be used to specify a SOCKS proxy at the same time --proxy is
used with an HTTP/HTTPS proxy (added in 7.52.0). In such a case, curl first
connects to the SOCKS proxy and then connects (through SOCKS) to the HTTP or
HTTPS proxy.
