c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: raw
Help: Do HTTP "raw"; no transfer decoding
Added: 7.16.2
Protocols: HTTP
Category: http
Example: --raw $URL
See-also: tr-encoding
---
When used, it disables all internal HTTP decoding of content or transfer
encodings and instead makes them passed on unaltered, raw.
