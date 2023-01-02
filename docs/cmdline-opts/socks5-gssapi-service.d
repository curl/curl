c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: socks5-gssapi-service
Arg: <name>
Help: SOCKS5 proxy service name for GSS-API
Added: 7.19.4
Category: proxy auth
Example: --socks5-gssapi-service sockd --socks5 hostname:4096 $URL
See-also: socks5
Multi: single
---
The default service name for a socks server is rcmd/server-fqdn. This option
allows you to change it.

Examples: --socks5 proxy-name --socks5-gssapi-service sockd would use
sockd/proxy-name --socks5 proxy-name --socks5-gssapi-service sockd/real-name
would use sockd/real-name for cases where the proxy-name does not match the
principal name.
