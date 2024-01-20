---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ciphers
Arg: <list of ciphers>
Help: SSL ciphers to use
Protocols: TLS
Category: tls
Added: 7.9
Multi: single
See-also:
  - tlsv1.3
  - tls13-ciphers
  - proxy-ciphers
Example:
  - --ciphers ECDHE-ECDSA-AES256-CCM8 $URL
---

# `--ciphers`

Specifies which ciphers to use in the connection. The list of ciphers must
specify valid ciphers. Read up on SSL cipher list details on this URL:

https://curl.se/docs/ssl-ciphers.html
