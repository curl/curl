---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-key-type
Arg: <type>
Help: Private key file type for proxy
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - proxy-key
  - proxy
Example:
  - --proxy-key-type DER --proxy-key here -x https://proxy.example $URL
---

# `--proxy-key-type`

Specify the private key file type your --proxy-key provided private key uses.
DER, PEM, ENG, and PROV are supported. If not specified, the default depends
on the TLS backend: PROV when using non-fork OpenSSL with provider support,
PEM otherwise.

Equivalent to --key-type but used in HTTPS proxy context.
