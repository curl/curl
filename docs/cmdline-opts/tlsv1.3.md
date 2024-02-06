---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlsv1.3
Help: Use TLSv1.3 or greater
Protocols: TLS
Added: 7.52.0
Category: tls
Multi: mutex
See-also:
  - tlsv1.2
  - tls-max
Example:
  - --tlsv1.3 $URL
---

# `--tlsv1.3`

Forces curl to use TLS version 1.3 or later when connecting to a remote TLS
server.

If the connection is done without TLS, this option has no effect. This
includes QUIC-using (HTTP/3) transfers.

Note that TLS 1.3 is not supported by all TLS backends.
