Long: proxy1.0
Arg: <host[:port]>
Help: Use HTTP/1.0 proxy on given port
Category: proxy
Example: --proxy1.0 -x http://proxy $URL
Added: 7.19.4
See-also: proxy socks5 preproxy
---
Use the specified HTTP 1.0 proxy. If the port number is not specified, it is
assumed at port 1080.

The only difference between this and the HTTP proxy option --proxy, is that
attempts to use CONNECT through the proxy will specify an HTTP 1.0 protocol
instead of the default HTTP 1.1.
