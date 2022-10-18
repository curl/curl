c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: http2
Tags: Versions
Protocols: HTTP
Added: 7.33.0
Mutexed: http1.1 http1.0 http2-prior-knowledge http3
Requires: HTTP/2
See-also: no-alpn
Help: Use HTTP 2
See-also: http1.1 http3
Category: http
Example: --http2 $URL
Multi: mutex
---
Tells curl to use HTTP version 2.

For HTTPS, this means curl will attempt to negotiate HTTP/2 in the TLS
handshake. curl does this by default.

For HTTP, this means curl will attempt to upgrade the request to HTTP/2 using
the Upgrade: request header.

When curl uses HTTP/2 over HTTPS, it does not itself insist on TLS 1.2 or
higher even though that is required by the specification. A user can add this
version requirement with --tlsv1.2.
