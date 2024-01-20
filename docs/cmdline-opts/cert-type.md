---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: cert-type
Protocols: TLS
Arg: <type>
Help: Certificate type (DER/PEM/ENG/P12)
Category: tls
Added: 7.9.3
Multi: single
See-also:
  - cert
  - key
  - key-type
Example:
  - --cert-type PEM --cert file $URL
---

# `--cert-type`

Tells curl what type the provided client certificate is using. PEM, DER, ENG
and P12 are recognized types.

The default type depends on the TLS backend and is usually PEM, however for
Secure Transport and Schannel it is P12. If --cert is a pkcs11: URI then ENG is
the default type.
