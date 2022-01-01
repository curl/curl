Long: haproxy-protocol-v2
Help: Send HAProxy PROXY protocol v2 header
Protocols: HTTP
Added: 7.82.0
Category: http proxy
Example: --haproxy-protocol-v2 $URL
See-also: proxy
Mutexed: haproxy-protocol
---
Send a HAProxy PROXY protocol v2 header at the beginning of the
connection. This is used by some load balancers and reverse proxies to
indicate the client's true IP address and port.

This option is primarily useful when sending test requests to a service that
expects this header.
