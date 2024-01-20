---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: engine
Arg: <name>
Help: Crypto engine to use
Protocols: TLS
Category: tls
Added: 7.9.3
Multi: single
See-also:
  - ciphers
  - curves
Example:
  - --engine flavor $URL
---

# `--engine`

Select the OpenSSL crypto engine to use for cipher operations. Use --engine
list to print a list of build-time supported engines. Note that not all (and
possibly none) of the engines may be available at runtime.
