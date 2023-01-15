c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlsv1.1
Help: Use TLSv1.1 or greater
Protocols: TLS
Added: 7.34.0
Category: tls
Example: --tlsv1.1 $URL
See-also: tlsv1.3 tls-max
Multi: mutex
---
Forces curl to use TLS version 1.1 or later when connecting to a remote TLS server.

In old versions of curl this option was documented to allow _only_ TLS 1.1.
That behavior was inconsistent depending on the TLS library. Use --tls-max if
you want to set a maximum TLS version.
