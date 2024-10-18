---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-tls13-ciphers
Arg: <list>
help: TLS 1.3 proxy cipher suites
Protocols: TLS
Category: proxy tls
Added: 7.61.0
Multi: single
See-also:
  - proxy-ciphers
  - tls13-ciphers
  - proxy
Example:
  - --proxy-tls13-ciphers TLS_AES_128_GCM_SHA256 -x proxy $URL
---

# `--proxy-tls13-ciphers`

Same as --tls13-ciphers but used in HTTPS proxy context.

Specify which cipher suites to use in the connection to your HTTPS proxy when
it negotiates TLS 1.3. The list of ciphers suites must specify valid ciphers.
Read up on TLS 1.3 cipher suite details on this URL:

https://curl.se/docs/ssl-ciphers.html

This option is used when curl is built to use OpenSSL 1.1.1 or later,
Schannel, wolfSSL, or mbedTLS 3.6.0 or later.

Before curl 8.10.0 with mbedTLS or wolfSSL, TLS 1.3 cipher suites were set
by using the --proxy-ciphers option.
