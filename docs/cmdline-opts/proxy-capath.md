---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-capath
Help: CA directory to verify peer against for proxy
Arg: <dir>
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - proxy-cacert
  - proxy
  - capath
Example:
  - --proxy-capath /local/directory -x https://proxy $URL
---

# `--proxy-capath`

Same as --capath but used in HTTPS proxy context.
