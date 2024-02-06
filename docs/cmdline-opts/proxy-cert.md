---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-cert
Arg: <cert[:passwd]>
Help: Set client certificate for proxy
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - proxy-cert-type
Example:
  - --proxy-cert file -x https://proxy $URL
---

# `--proxy-cert`

Same as --cert but used in HTTPS proxy context.
