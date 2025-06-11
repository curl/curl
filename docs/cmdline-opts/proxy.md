---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy
Short: x
Arg: <[protocol://]host[:port]>
Help: Use this proxy
Category: proxy
Added: 4.0
Multi: single
See-also:
  - socks5
  - proxy-basic
Example:
  - --proxy http://proxy.example $URL
---

# `--proxy`

Use the specified proxy.

The proxy string can be specified with a protocol:// prefix. No protocol
specified or http:// it is treated as an HTTP proxy. Use socks4://,
socks4a://, socks5:// or socks5h:// to request a specific SOCKS version to be
used. (Added in 7.21.7)

Unix domain sockets are supported for socks proxy. Set localhost for the host
part. e.g. socks5h://localhost/path/to/socket.sock

HTTPS proxy support works with the https:// protocol prefix for OpenSSL and
GnuTLS (added in 7.52.0). It also works for mbedTLS, Rustls, Schannel and
wolfSSL (added in 7.87.0).

Unrecognized and unsupported proxy protocols cause an error (added in 7.52.0).
Ancient curl versions ignored unknown schemes and used http:// instead.

If the port number is not specified in the proxy string, it is assumed to be
1080.

This option overrides existing environment variables that set the proxy to
use. If there is an environment variable setting a proxy, you can set proxy to
"" to override it.

All operations that are performed over an HTTP proxy are transparently
converted to HTTP. It means that certain protocol specific operations might
not be available. This is not the case if you can tunnel through the proxy, as
one with the --proxytunnel option.

User and password that might be provided in the proxy string are URL decoded
by curl. This allows you to pass in special characters such as @ by using %40
or pass in a colon with %3a.

The proxy host can be specified the same way as the proxy environment
variables, including the protocol prefix (http://) and the embedded user +
password.

When a proxy is used, the active FTP mode as set with --ftp-port, cannot be
used.

Doing FTP over an HTTP proxy without --proxytunnel makes curl do HTTP with an
FTP URL over the proxy. For such transfers, common FTP specific options do not
work, including --ssl-reqd and --ftp-ssl-control.
