---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: http3-only
Tags: Versions
Protocols: HTTP
Added: 7.88.0
Mutexed: http1.1 http1.0 http2 http2-prior-knowledge http3
Requires: HTTP/3
Help: Use HTTP v3 only
Category: http
Multi: mutex
See-also:
  - http1.1
  - http2
  - http3
Example:
  - --http3-only $URL
---

# `--http3-only`

Instructs curl to use HTTP/3 to the host in the URL, with no fallback to
earlier HTTP versions. HTTP/3 can only be used for HTTPS and not for HTTP
URLs. For HTTP, this option triggers an error.

This option allows a user to avoid using the Alt-Svc method of upgrading to
HTTP/3 when you know that the target speaks HTTP/3 on the given host and port.

This option makes curl fail if a QUIC connection cannot be established, it
does not attempt any other HTTP versions on its own. Use --http3 for similar
functionality *with* a fallback.
