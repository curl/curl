---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: doh-insecure
Help: Allow insecure DoH server connections
Added: 7.76.0
Category: dns tls
Multi: boolean
See-also:
  - doh-url
Example:
  - --doh-insecure --doh-url https://doh.example $URL
---

# `--doh-insecure`

Same as --insecure but used for DoH (DNS-over-HTTPS).
