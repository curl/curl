---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-tlsv1
Help: Use TLSv1 for HTTPS proxy
Added: 7.52.0
Category: proxy tls auth
Multi: mutex
See-also:
  - proxy
Example:
  - --proxy-tlsv1 -x https://proxy $URL
---

# `--proxy-tlsv1`

Same as --tlsv1 but used in HTTPS proxy context.
