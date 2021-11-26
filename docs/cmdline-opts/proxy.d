Long: proxy
Short: x
Arg: [protocol://]host[:port]
Help: Use this proxy
Category: proxy
Example: --proxy http://proxy.example $URL
Added: 4.0
See-also: socks5 proxy-basic
---
Use the specified proxy.

The proxy string can be specified with a protocol:// prefix. No protocol
specified or http:// will be treated as HTTP proxy. Use socks4://, socks4a://,
socks5:// or socks5h:// to request a specific SOCKS version to be used.
(Added in 7.21.7)

HTTPS proxy support via https:// protocol prefix was added in 7.52.0 for
OpenSSL, GnuTLS and NSS.

Unrecognized and unsupported proxy protocols cause an error since 7.52.0.
Prior versions may ignore the protocol and use http:// instead.

If the port number is not specified in the proxy string, it is assumed to be
1080.

This option overrides existing environment variables that set the proxy to
use. If there's an environment variable setting a proxy, you can set proxy to
\&"" to override it.

All operations that are performed over an HTTP proxy will transparently be
converted to HTTP. It means that certain protocol specific operations might
not be available. This is not the case if you can tunnel through the proxy, as
one with the --proxytunnel option.

User and password that might be provided in the proxy string are URL decoded
by curl. This allows you to pass in special characters such as @ by using %40
or pass in a colon with %3a.

The proxy host can be specified the same way as the proxy environment
variables, including the protocol prefix (http://) and the embedded user +
password.

If this option is used several times, the last one will be used.
