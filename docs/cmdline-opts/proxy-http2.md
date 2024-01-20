---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-http2
Tags: Versions HTTP/2
Protocols: HTTP
Added: 8.1.0
Mutexed:
Requires: HTTP/2
Help: Use HTTP/2 with HTTPS proxy
Category: http proxy
Multi: boolean
See-also:
  - proxy
Example:
  - --proxy-http2 -x proxy $URL
---

# `--proxy-http2`

Tells curl to try negotiate HTTP version 2 with an HTTPS proxy. The proxy might
still only offer HTTP/1 and then curl sticks to using that version.

This has no effect for any other kinds of proxies.
