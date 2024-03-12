---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: http3
Tags: Versions
Protocols: HTTP
Added: 7.66.0
Mutexed: http1.1 http1.0 http2 http2-prior-knowledge http3-only
Requires: HTTP/3
Help: Use HTTP v3
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
if the HTTP/3 connection establishment fails. HTTP/3 is only available for
HTTPS and not for HTTP URLs.

This option allows a user to avoid using the Alt-Svc method of upgrading to
HTTP/3 when you know that the target speaks HTTP/3 on the given host and port.

When asked to use HTTP/3, curl issues a separate attempt to use older HTTP
versions with a slight delay, so if the HTTP/3 transfer fails or is slow, curl
still tries to proceed with an older HTTP version.

Use --http3-only for similar functionality *without* a fallback.
