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
  - proxy-key
Example:
  - --proxy-cert-type PEM --proxy-cert file -x https://proxy $URL
---

# `--proxy-cert-type`

Set type of the provided client certificate when using HTTPS proxy. PEM, DER,
ENG, PROV and P12 are recognized types.

The default type depends on the TLS backend and is usually PEM. For Schannel
it is P12. If --proxy-cert is a pkcs11: URI then ENG or PROV is the default
type (depending on OpenSSL version).

Equivalent to --cert-type but used in HTTPS proxy context.
