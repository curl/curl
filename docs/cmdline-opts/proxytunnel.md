---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxytunnel
Short: p
Help: HTTP proxy tunnel (using CONNECT)
Category: proxy
Added: 7.3
Multi: boolean
See-also:
  - proxy
Example:
  - --proxytunnel -x http://proxy $URL
---

# `--proxytunnel`

When an HTTP proxy is used --proxy, this option makes curl tunnel the traffic
through the proxy. The tunnel approach is made with the HTTP proxy CONNECT
request and requires that the proxy allows direct connection to the remote port
number curl wants to tunnel through to.

To suppress proxy CONNECT response headers when curl is set to output headers
use --suppress-connect-headers.
