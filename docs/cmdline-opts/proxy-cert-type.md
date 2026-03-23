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
  - --proxy-cert-type PEM --proxy-cert file -x https://proxy.example $URL
---

# `--proxy-cert-type`

Set type of the provided client certificate when using HTTPS proxy. PEM, DER,
ENG, PROV and P12 are recognized types.

The default type depends on the TLS backend: PROV when using non-fork OpenSSL
with provider support, P12 for Schannel, and PEM otherwise.

Equivalent to --cert-type but used in HTTPS proxy context.
