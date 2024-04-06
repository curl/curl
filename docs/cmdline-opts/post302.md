---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: post302
Help: Do not switch to GET after a 302 redirect
Protocols: HTTP
Added: 7.19.1
Category: http post
Multi: boolean
See-also:
  - post301
  - post303
  - location
Example:
  - --post302 --location -d "data" $URL
---

# `--post302`

Respect RFC 7231/6.4.3 and do not convert POST requests into GET requests when
following a 302 redirect. The non-RFC behavior is ubiquitous in web browsers,
so curl does the conversion by default to maintain consistency. However, a
server may require a POST to remain a POST after such a redirection. This
option is meaningful only when using --location.
