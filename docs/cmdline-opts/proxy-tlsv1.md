---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-tlsv1
Help: TLSv1 for HTTPS proxy
Added: 7.52.0
Category: proxy tls auth
Multi: mutex
See-also:
  - proxy
Example:
  - --proxy-tlsv1 -x https://proxy $URL
---

# `--proxy-tlsv1`

Use at least TLS version 1.x when negotiating with an HTTPS proxy. That means
TLS version 1.0 or higher

Equivalent to --tlsv1 but for an HTTPS proxy context.
