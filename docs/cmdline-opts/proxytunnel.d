Long: proxytunnel
Short: p
Help: Operate through a HTTP proxy tunnel (using CONNECT)
See-also: proxy
---
When an HTTP proxy is used --proxy, this option will cause non-HTTP protocols
to attempt to tunnel through the proxy instead of merely using it to do
HTTP-like operations. The tunnel approach is made with the HTTP proxy CONNECT
request and requires that the proxy allows direct connect to the remote port
number curl wants to tunnel through to.

To suppress proxy CONNECT response headers when curl is set to output headers
use --suppress-connect-headers.
