Long: socks5-gssapi
Help: Enable GSS-API auth for SOCKS5 proxies
Added: 7.55.0
Category: proxy auth
---
Tells curl to use GSS-API authentication when connecting to a SOCKS5 proxy.
The GSS-API authentication is enabled by default (if curl is compiled with
GSS-API support).  Use --socks5-basic to force username/password authentication
to SOCKS5 proxies.
