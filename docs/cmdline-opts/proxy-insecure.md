---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-insecure
Help: Do HTTPS proxy connections without verifying the proxy
Added: 7.52.0
Category: proxy tls
Multi: boolean
See-also:
  - proxy
  - insecure
Example:
  - --proxy-insecure -x https://proxy $URL
---

# `--proxy-insecure`

Same as --insecure but used in HTTPS proxy context.
