---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: compressed
Help: Request compressed response
Protocols: HTTP
Category: http common
Added: 7.10
Multi: boolean
See-also:
  - compressed-ssh
Example:
  - --compressed $URL
---

# `--compressed`

Request a compressed response using one of the algorithms curl supports, and
automatically decompress the content.

Response headers are not modified when saved, so if they are "interpreted"
separately again at a later point they might appear to be saying that the
content is (still) compressed; while in fact it has already been decompressed.

If this option is used and the server sends an unsupported encoding, curl
reports an error. This is a request, not an order; the server may or may not
deliver data compressed.
