---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-cert-type
Arg: <type>
Added: 7.52.0
Help: Client certificate type for HTTPS proxy
Category: proxy tls
Multi: single
See-also:
  - proxy-cert
Example:
  - --proxy-cert-type PEM --proxy-cert file -x https://proxy $URL
---

# `--proxy-cert-type`

Same as --cert-type but used in HTTPS proxy context.
