---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: 2
Long: sslv2
Tags: Versions
Protocols: SSL
Added: 5.9
Mutexed: sslv3 tlsv1 tlsv1.1 tlsv1.2
Requires: TLS
Help: SSLv2
Category: tls
Multi: mutex
See-also:
  - http1.1
  - http2
Example:
  - --sslv2 $URL
---

# `--sslv2`

This option previously asked curl to use SSLv2, but is now ignored
(added in 7.77.0). SSLv2 is widely considered insecure (see RFC 6176).
