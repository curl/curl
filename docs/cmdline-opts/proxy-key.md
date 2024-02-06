---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-key
Help: Private key for HTTPS proxy
Arg: <key>
Category: proxy tls
Added: 7.52.0
Multi: single
See-also:
  - proxy-key-type
  - proxy
Example:
  - --proxy-key here -x https://proxy $URL
---

# `--proxy-key`

Same as --key but used in HTTPS proxy context.
