---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-alpn
Tags: HTTP/2
Protocols: HTTPS
Added: 7.36.0
Requires: TLS
Help: Disable the ALPN TLS extension
Category: tls http
Multi: boolean
See-also:
  - no-npn
  - http2
Example:
  - --no-alpn $URL
---

# `--no-alpn`

Disable the ALPN TLS extension. ALPN is enabled by default if libcurl was built
with an SSL library that supports ALPN. ALPN is used by a libcurl that supports
HTTP/2 to negotiate HTTP/2 support with the server during https sessions.

Note that this is the negated option name documented. You can use --alpn to
enable ALPN.
