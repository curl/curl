---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: http3
Tags: Versions
Protocols: HTTP
Added: 7.66.0
Mutexed: http1.1 http1.0 http2 http2-prior-knowledge http3-only
Requires: HTTP/3
Help: Use HTTP/3 with optional QUIC version (v1 or v2)
Category: http
Multi: mutex
See-also:
  - http1.1
  - http2
Example:
  - --http3 $URL
---

# `--http3`

Attempt HTTP/3 to the host in the URL, but fallback to earlier HTTP versions
if the HTTP/3 connection establishment fails or is slow. HTTP/3 is only
available for HTTPS and not for HTTP URLs.

This option allows specifying which version of QUIC to use for HTTP/3. Provide
an argument `v1` (for QUICv1, the default) or `v2` (for QUICv2). If no
argument is provided, `v1` is used.

This option allows a user to avoid using the Alt-Svc method of upgrading to
HTTP/3 when you know or suspect that the target speaks HTTP/3 on the given
host and port.

When asked to use HTTP/3, curl issues a separate attempt to use older HTTP
versions with a slight delay, so if the HTTP/3 transfer fails or is slow, curl
still tries to proceed with an older HTTP version. The fallback performs the
regular negotiation between HTTP/1 and HTTP/2.

Use --http3-only for similar functionality *without* a fallback.

## Examples

To attempt HTTP/3 (QUICv1 by default):
`curl --http3 https://example.com`

To attempt HTTP/3 with QUICv1 explicitly:
`curl --http3 v1 https://example.com`

To attempt HTTP/3 with QUICv2:
`curl --http3 v2 https://example.com`
