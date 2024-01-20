---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: socks5-basic
Help: Enable username/password auth for SOCKS5 proxies
Added: 7.55.0
Category: proxy auth
Multi: mutex
See-also:
  - socks5
Example:
  - --socks5-basic --socks5 hostname:4096 $URL
---

# `--socks5-basic`

Tells curl to use username/password authentication when connecting to a SOCKS5
proxy. The username/password authentication is enabled by default. Use
--socks5-gssapi to force GSS-API authentication to SOCKS5 proxies.
