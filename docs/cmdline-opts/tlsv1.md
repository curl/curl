---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: 1
Long: tlsv1
Tags: Versions
Protocols: TLS
Added: 7.9.2
Mutexed: tlsv1.1 tlsv1.2 tlsv1.3
Requires: TLS
Help: Use TLSv1.0 or greater
Category: tls
Multi: mutex
See-also:
  - http1.1
  - http2
Example:
  - --tlsv1 $URL
---

# `--tlsv1`

Tells curl to use at least TLS version 1.x when negotiating with a remote TLS
server. That means TLS version 1.0 or higher
