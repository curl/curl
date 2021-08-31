Long: http2-prior-knowledge
Tags: Versions
Protocols: HTTP
Added: 7.49.0
Mutexed: http1.1 http1.0 http2
Requires: HTTP/2
Help: Use HTTP 2 without HTTP/1.1 Upgrade
Category: http
Example: --http2-prior-knowledge $URL
---
Tells curl to issue its non-TLS HTTP requests using HTTP/2 without HTTP/1.1
Upgrade. It requires prior knowledge that the server supports HTTP/2 straight
away. HTTPS requests will still do HTTP/2 the standard way with negotiated
protocol version in the TLS handshake.
