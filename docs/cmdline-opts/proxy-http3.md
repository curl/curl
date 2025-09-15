---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-http3
Tags: Versions HTTP/3
Protocols: HTTP
Added: 8.17.0
Mutexed:
Requires: HTTP/3
Help: Use HTTP/3 with HTTPS proxy
Category: http proxy
Multi: boolean
See-also:
  - proxy
  - proxy-http2
Example:
  - --proxy-http3 -x proxy $URL
---

# `--proxy-http3`

Negotiate HTTP/3 with an HTTPS proxy.
Fails to perform the transfer if the given proxy does not support HTTP/3.

This has no effect for any other kinds of proxies.
