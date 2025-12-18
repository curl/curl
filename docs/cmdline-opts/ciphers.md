---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ciphers
Arg: <list>
Help: TLS 1.2 (1.1, 1.0) ciphers to use
Protocols: TLS
Category: tls
Added: 7.9
Multi: single
See-also:
  - tls13-ciphers
  - proxy-ciphers
  - curves
Example:
  - --ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256 $URL
---

# `--ciphers`

Specify which cipher suites to use in the connection if it negotiates TLS 1.2
(1.1, 1.0). The list of ciphers suites must specify valid ciphers. Read up on
cipher suite details on this URL:

https://curl.se/docs/ssl-ciphers.html
