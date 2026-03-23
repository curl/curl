---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxyudptunnel
Help: HTTP proxy tunnel (using CONNECT-UDP)
Category: proxy
Added: 8.20.0
Mutexed: proxytunnel
Requires: HTTP/3
Multi: boolean
See-also:
  - proxy
  - proxytunnel
Example:
  - --proxyudptunnel -x http://proxy $URL
---

# `--proxyudptunnel`

When an HTTP proxy is used with --proxy, this option makes curl tunnel
the traffic through the proxy using the CONNECT-UDP method. The tunnel
is established by sending a CONNECT-UDP request to the proxy, asking it
to relay UDP traffic to the remote host and port. This requires that
the proxy supports the CONNECT-UDP method and allows access to the
requested destination.

This option is mutually exclusive with `--proxytunnel`.
