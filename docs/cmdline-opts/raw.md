---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: raw
Help: Do HTTP raw; no transfer decoding
Added: 7.16.2
Protocols: HTTP
Category: http
Multi: boolean
See-also:
  - tr-encoding
Example:
  - --raw $URL
---

# `--raw`

When used, it disables all internal HTTP decoding of content or transfer
encodings and instead makes them passed on unaltered, raw.

Beware that when ignoring HTTP/1.1 chunked transfer encoding, curl might not
detect the end of the response body and might instead sit idly waiting for the
connection to eventually close.
