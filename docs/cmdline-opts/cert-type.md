---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: cert-type
Protocols: TLS
Arg: <type>
Help: Certificate type (DER/PEM/ENG/PROV/P12)
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

Set type of the provided client certificate. PEM, DER, ENG, PROV and P12 are
recognized types.

The default type depends on the TLS backend: PROV when using non-fork OpenSSL
with provider support, P12 for Schannel, and PEM otherwise.
