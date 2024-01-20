---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: http0.9
Tags: Versions
Protocols: HTTP
Help: Allow HTTP 0.9 responses
Category: http
Added: 7.64.0
Multi: boolean
See-also:
  - http1.1
  - http2
  - http3
Example:
  - --http0.9 $URL
---

# `--http0.9`

Tells curl to be fine with HTTP version 0.9 response.

HTTP/0.9 is a response without headers and therefore you can also connect with
this to non-HTTP servers and still get a response since curl simply
transparently downgrades - if allowed.

HTTP/0.9 is disabled by default (added in 7.66.0)
