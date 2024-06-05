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
  - insecure
  - proxy-insecure
Example:
  - --doh-insecure --doh-url https://doh.example $URL
---

# `--doh-insecure`

By default, every connection curl makes to a DoH server is verified to be
secure before the transfer takes place. This option tells curl to skip the
verification step and proceed without checking.

**WARNING**: using this option makes the DoH transfer and name resolution
insecure.

This option is equivalent to --insecure and --proxy-insecure but used for DoH
(DNS-over-HTTPS) only.
