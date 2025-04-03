---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: doh-cert-status
Help: Verify DoH server cert status OCSP-staple
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

Verify the status of the DoH servers' certificate by using the Certificate
Status Request (aka. OCSP stapling) TLS extension.

If this option is enabled and the DoH server sends an invalid (e.g. expired)
response, if the response suggests that the server certificate has been
revoked, or no response at all is received, the verification fails.

This support is currently only implemented in the OpenSSL and GnuTLS backends.
