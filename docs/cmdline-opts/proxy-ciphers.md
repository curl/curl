---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ciphers
Arg: <list>
Help: TLS 1.2 (1.1, 1.0) ciphers to use for proxy
Protocols: TLS
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - proxy-tls13-ciphers
  - ciphers
  - proxy
Example:
  - --proxy-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256 -x https://proxy $URL
---

# `--proxy-ciphers`

Same as --ciphers but used in HTTPS proxy context.

Specify which cipher suites to use in the connection to your HTTPS proxy when
it negotiates TLS 1.2 (1.1, 1.0). The list of ciphers suites must specify
valid ciphers. Read up on cipher suite details on this URL:

https://curl.se/docs/ssl-ciphers.html
