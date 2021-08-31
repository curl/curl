Long: http2
Tags: Versions
Protocols: HTTP
Added: 7.33.0
Mutexed: http1.1 http1.0 http2-prior-knowledge
Requires: HTTP/2
See-also: no-alpn
Help: Use HTTP 2
See-also: http1.1 http3
Category: http
Example: --http2 $URL
---
Tells curl to use HTTP version 2.

For HTTPS, this means curl will attempt to negotiate HTTP/2 in the TLS
handshake. curl does this by default.

For HTTP, this means curl will attempt to upgrade the request to HTTP/2 using
the Upgrade: request header.
