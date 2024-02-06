---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: doh-cert-status
Help: Verify the status of the DoH server cert via OCSP-staple
Added: 7.76.0
Category: dns tls
Multi: boolean
See-also:
  - doh-insecure
Example:
  - --doh-cert-status --doh-url https://doh.example $URL
---

# `--doh-cert-status`

Same as --cert-status but used for DoH (DNS-over-HTTPS).
