---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ssl-allow-beast
Help: Allow security flaw for interop for HTTPS proxy
Added: 7.52.0
Category: proxy tls
Multi: boolean
See-also:
  - ssl-allow-beast
  - proxy
Example:
  - --proxy-ssl-allow-beast -x https://proxy $URL
---

# `--proxy-ssl-allow-beast`

Same as --ssl-allow-beast but used in HTTPS proxy context.
