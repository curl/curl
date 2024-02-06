---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-crlfile
Arg: <file>
Help: Set a CRL list for proxy
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - crlfile
  - proxy
Example:
  - --proxy-crlfile rejects.txt -x https://proxy $URL
---

# `--proxy-crlfile`

Same as --crlfile but used in HTTPS proxy context.
