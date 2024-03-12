---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: socks5-gssapi-service
Arg: <name>
Help: SOCKS5 proxy service name for GSS-API
Added: 7.19.4
Category: proxy auth
Multi: single
See-also:
  - socks5
Example:
  - --socks5-gssapi-service sockd --socks5 hostname:4096 $URL
---

# `--socks5-gssapi-service`

Set the service name for a socks server. Default is **rcmd/server-fqdn**.
