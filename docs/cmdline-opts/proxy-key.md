---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-key
Help: Private key for HTTPS proxy
Arg: <key>
Category: proxy tls
Added: 7.52.0
Multi: single
See-also:
  - proxy-key-type
  - proxy
Example:
  - --proxy-key here -x https://proxy $URL
---

# `--proxy-key`

Specify the filename for your private key when using client certificates with
your HTTPS proxy. This option is the equivalent to --key but used in HTTPS
proxy context.
