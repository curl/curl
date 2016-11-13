Short:
Long: no-alpn
Tags:
Protocols: HTTPS
Added: 7.36.0
Mutexed:
See-also: no-npn http2
Requires: TLS
---
Disable the ALPN TLS extension. ALPN is enabled by default if libcurl was built
with an SSL library that supports ALPN. ALPN is used by a libcurl that supports
HTTP/2 to negotiate HTTP/2 support with the server during https sessions.
