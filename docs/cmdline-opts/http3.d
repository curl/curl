c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: http3
Tags: Versions
Protocols: HTTP
Added: 7.66.0
Mutexed: http1.1 http1.0 http2 http2-prior-knowledge
Requires: HTTP/3
Help: Use HTTP v3
See-also: http1.1 http2
Category: http
Example: --http3 $URL
---
**WARNING**: this option is experimental. Do not use in production.

Tells curl to use HTTP version 3 directly to the host and port number used in
the URL. A normal HTTP/3 transaction will be done to a host and then get
redirected via Alt-Svc, but this option allows a user to circumvent that when
you know that the target speaks HTTP/3 on the given host and port.

This option will make curl fail if a QUIC connection cannot be established, it
cannot fall back to a lower HTTP version on its own.
