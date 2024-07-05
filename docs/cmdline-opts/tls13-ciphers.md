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
  - curves
  - proxy-tls13-ciphers
Example:
  - --tls13-ciphers TLS_AES_128_GCM_SHA256 $URL
---

# `--tls13-ciphers`

Specifies which cipher suites to use in the connection if it negotiates TLS
1.3. The list of ciphers suites must specify valid ciphers. Read up on TLS 1.3
cipher suite details on this URL:

https://curl.se/docs/ssl-ciphers.html

This option is currently used only when curl is built to use OpenSSL 1.1.1 or
later, or Schannel. If you are using a different SSL backend you can try
setting TLS 1.3 cipher suites by using the --ciphers option.

With curl 8.10 or newer, TLS 1.3 ciphers for OpenSSL may be configured with
`--ciphers` also under the following conditions:
- only 1.3 ciphers are mentioned
- the minimum and maximum TLS versions are unspecified or at least 1.3

Setting 1.3 ciphers via `--ciphers` implies that the minimum TLS version
to negotiate is at least 1.3.
