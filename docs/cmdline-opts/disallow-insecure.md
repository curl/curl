---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: disallow-insecure
Help: Reject insecure TLS options
Added: 8.21.0
Category: tls
Multi: boolean
See-also:
  - insecure
  - proxy-insecure
  - doh-insecure
Example:
  - --disallow-insecure https://example.com
---

# `--disallow-insecure`

Refuse command lines that include the insecure TLS options `--insecure`,
`--proxy-insecure` or `--doh-insecure`.

This option is meant for policy-constrained environments where disabling TLS
verification must be prevented.
