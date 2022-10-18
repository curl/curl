c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: doh-cert-status
Help: Verify the status of the DoH server cert via OCSP-staple
Added: 7.76.0
Category: dns tls
Example: --doh-cert-status --doh-url https://doh.example $URL
See-also: doh-insecure
Multi: boolean
---
Same as --cert-status but used for DoH (DNS-over-HTTPS).
