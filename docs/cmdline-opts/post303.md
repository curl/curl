---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: post303
Help: Do not switch to GET after a 303 redirect
Protocols: HTTP
Added: 7.26.0
Category: http post
Multi: boolean
See-also:
  - post302
  - post301
  - location
Example:
  - --post303 --location -d "data" $URL
---

# `--post303`

Violate RFC 7231/6.4.4 and do not convert POST requests into GET requests when
following 303 redirect. A server may require a POST to remain a POST after a
303 redirection. This option is meaningful only when using --location.
