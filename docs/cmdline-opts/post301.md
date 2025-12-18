---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: post301
Help: Do not switch to GET after a 301 redirect
Protocols: HTTP
Added: 7.17.1
Category: http post
Multi: boolean
See-also:
  - post302
  - post303
  - location
Example:
  - --post301 --location -d "data" $URL
---

# `--post301`

Respect RFC 7231/6.4.2 and do not convert POST requests into GET requests when
following a 301 redirect. The non-RFC behavior is ubiquitous in web browsers,
so curl does the conversion by default to maintain consistency. However, a
server may require a POST to remain a POST after such a redirection. This
option is meaningful only when using --location.
