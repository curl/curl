---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: preproxy
Arg: <[protocol://]host[:port]>
Help: Use this proxy first
Added: 7.52.0
Category: proxy
Multi: single
See-also:
  - proxy
  - socks5
Example:
  - --preproxy socks5://proxy.example -x http://http.example $URL
---

# `--preproxy`

Use the specified SOCKS proxy before connecting to an HTTP or HTTPS --proxy. In
such a case curl first connects to the SOCKS proxy and then connects (through
SOCKS) to the HTTP or HTTPS proxy. Hence pre proxy.

The pre proxy string should be specified with a protocol:// prefix to specify
alternative proxy protocols. Use socks4://, socks4a://, socks5:// or
socks5h:// to request the specific SOCKS version to be used. No protocol
specified makes curl default to SOCKS4.

If the port number is not specified in the proxy string, it is assumed to be
1080.

User and password that might be provided in the proxy string are URL decoded
by curl. This allows you to pass in special characters such as @ by using %40
or pass in a colon with %3a.
