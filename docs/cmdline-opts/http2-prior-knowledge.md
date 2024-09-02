---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: http2-prior-knowledge
Tags: Versions
Protocols: HTTP
Added: 7.49.0
Mutexed: http1.1 http1.0 http2 http3
Requires: HTTP/2
Help: Use HTTP 2 without HTTP/1.1 Upgrade
Category: http
Multi: boolean
See-also:
  - http2
  - http3
Example:
  - --http2-prior-knowledge $URL
---

# `--http2-prior-knowledge`

Issue a non-TLS HTTP requests using HTTP/2 directly without HTTP/1.1 Upgrade.
It requires prior knowledge that the server supports HTTP/2 straight away.
HTTPS requests still do HTTP/2 the standard way with negotiated protocol
version in the TLS handshake.

Since 8.10.0 if this option is set for an HTTPS request then the application
layer protocol version (ALPN) offered to the server is only HTTP/2. Prior to
that both HTTP/1.1 and HTTP/2 were offered.
