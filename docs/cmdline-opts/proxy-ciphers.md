---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ciphers
Arg: <list>
Help: SSL ciphers to use for proxy
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - ciphers
  - curves
  - proxy
Example:
  - --proxy-ciphers ECDHE-ECDSA-AES256-CCM8 -x https://proxy $URL
---

# `--proxy-ciphers`

Same as --ciphers but used in HTTPS proxy context.

Specifies which ciphers to use in the connection to the HTTPS proxy. The list
of ciphers must specify valid ciphers. Read up on SSL cipher list details on
this URL:

https://curl.se/docs/ssl-ciphers.html
