Long: proxy
Short: x
Arg: [protocol://]host[:port]
Help: Use this proxy
---
Use the specified proxy.

The proxy string can be specified with a protocol:// prefix to specify
alternative proxy protocols. Use socks4://, socks4a://, socks5:// or
socks5h:// to request the specific SOCKS version to be used. No protocol
specified, http:// and all others will be treated as HTTP proxies. (The
protocol support was added in curl 7.21.7)

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

The proxy host can be specified the exact same way as the proxy environment
variables, including the protocol prefix (http://) and the embedded user +
password.

If this option is used several times, the last one will be used.
