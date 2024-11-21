---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tls13-ciphers
Arg: <list>
help: TLS 1.3 cipher suites to use
Protocols: TLS
Category: tls
Added: 7.61.0
Multi: single
See-also:
  - ciphers
  - proxy-tls13-ciphers
  - curves
Example:
  - --tls13-ciphers TLS_AES_128_GCM_SHA256 $URL
---

# `--tls13-ciphers`

Specifies which cipher suites to use in the connection if it negotiates TLS
1.3. The list of ciphers suites must specify valid ciphers. Read up on TLS 1.3
cipher suite details on this URL:

https://curl.se/docs/ssl-ciphers.html

This option is used when curl is built to use OpenSSL 1.1.1 or later,
wolfSSL, or mbedTLS 3.6.0 or later.

Before curl 8.10.0 with mbedTLS or wolfSSL, TLS 1.3 cipher suites were set
by using the --ciphers option.
