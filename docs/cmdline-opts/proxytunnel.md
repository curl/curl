---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
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

When an HTTP proxy is used --proxy, this option makes fetch tunnel the traffic
through the proxy. The tunnel approach is made with the HTTP proxy CONNECT
request and requires that the proxy allows direct connect to the remote port
number fetch wants to tunnel through to.

To suppress proxy CONNECT response headers when fetch is set to output headers
use --suppress-connect-headers.
