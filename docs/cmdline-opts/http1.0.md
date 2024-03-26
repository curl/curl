---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: 0
Long: http1.0
Tags: Versions
Protocols: HTTP
Added: 7.9.1
Mutexed: http1.1 http2 http2-prior-knowledge http3
Help: Use HTTP 1.0
Category: http
Multi: mutex
See-also:
  - http0.9
  - http1.1
Example:
  - --http1.0 $URL
---

# `--http1.0`

Use HTTP version 1.0 instead of using its internally preferred HTTP version.
