---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-cacert
Help: CA certificates to verify proxy against
Arg: <file>
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - proxy-capath
  - cacert
  - capath
  - proxy
Example:
  - --proxy-cacert CA-file.txt -x https://proxy $URL
---

# `--proxy-cacert`

Same as --cacert but used in HTTPS proxy context.
