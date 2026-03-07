---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: http1.1
Tags: Versions
Protocols: HTTP
Added: 7.33.0
Mutexed: http1.0 http2 http2-prior-knowledge http3
Help: Use HTTP/1.1
Category: http
Multi: mutex
See-also:
  - http1.0
  - http0.9
Example:
  - --http1.1 $URL
---

# `--http1.1`

Use HTTP version 1.1. This is the default with HTTP:// URLs.
