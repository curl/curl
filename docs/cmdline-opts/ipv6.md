---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: 6
Long: ipv6
Tags: Versions
Protocols:
Added: 7.10.8
Mutexed: ipv4
Requires:
Help: Resolve names to IPv6 addresses
Category: connection dns
Multi: mutex
See-also:
  - http1.1
  - http2
Example:
  - --ipv6 $URL
---

# `--ipv6`

Request only IPv6 addresses when resolving hostnames, and not for example any
IPv4.

Your resolver may still respond to an IPv6-only resolve request by returning
IPv6 addresses that contain "mapped" IPv4 addresses for compatibility purposes.
macOS is known to do this.
