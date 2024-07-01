---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-pass
Arg: <phrase>
Help: Passphrase for private key for HTTPS proxy
Added: 7.52.0
Category: proxy tls auth
Multi: single
See-also:
  - proxy
  - proxy-key
Example:
  - --proxy-pass secret --proxy-key here -x https://proxy $URL
---

# `--proxy-pass`

Passphrase for the private key for HTTPS proxy client certificate.

Equivalent to --pass but used in HTTPS proxy context.
