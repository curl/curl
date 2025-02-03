---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: http2
Tags: Versions
Protocols: HTTP
Added: 7.33.0
Mutexed: http1.1 http1.0 http2-prior-knowledge http3
Requires: HTTP/2
Help: Use HTTP/2
Category: http
Multi: mutex
See-also:
  - http1.1
  - http3
  - no-alpn
Example:
  - --http2 $URL
---

# `--http2`

Use HTTP/2.

For HTTPS, this means fetch negotiates HTTP/2 in the TLS handshake. fetch does
this by default.

For HTTP, this means fetch attempts to upgrade the request to HTTP/2 using the
Upgrade: request header.

When fetch uses HTTP/2 over HTTPS, it does not itself insist on TLS 1.2 or
higher even though that is required by the specification. A user can add this
version requirement with --tlsv1.2.
