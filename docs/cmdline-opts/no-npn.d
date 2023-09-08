c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-npn
Tags: Versions HTTP/2
Protocols: HTTPS
Added: 7.36.0
Mutexed:
See-also: no-alpn http2
Requires: TLS
Help: Disable the NPN TLS extension
Category: tls http
Example: --no-npn $URL
Multi: boolean
---
curl never uses NPN, this option has no effect (added in 7.86.0).

Disable the NPN TLS extension. NPN is enabled by default if libcurl was built
with an SSL library that supports NPN. NPN is used by a libcurl that supports
HTTP/2 to negotiate HTTP/2 support with the server during https sessions.
