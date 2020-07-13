Long: proxytunnel
Short: p
Help: Operate through an HTTP proxy tunnel (using CONNECT)
See-also: proxy
Category: proxy
---
When an HTTP proxy is used --proxy, this option will make curl tunnel through
the proxy. The tunnel approach is made with the HTTP proxy CONNECT request and
requires that the proxy allows direct connect to the remote port number curl
wants to tunnel through to.

To suppress proxy CONNECT response headers when curl is set to output headers
use --suppress-connect-headers.
