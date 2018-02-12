Long: no-npn
Tags: Versions HTTP/2
Protocols: HTTPS
Added: 7.36.0
Mutexed:
See-also: no-alpn http2
Requires: TLS
Help: Disable the NPN TLS extension
---
Disable the NPN TLS extension. NPN is enabled by default if libcurl was built
with an SSL library that supports NPN. NPN is used by a libcurl that supports
HTTP/2 to negotiate HTTP/2 support with the server during https sessions.
