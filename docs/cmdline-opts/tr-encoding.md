---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tr-encoding
Added: 7.21.6
Help: Request compressed transfer encoding
Protocols: HTTP
Category: http
Multi: boolean
See-also:
  - compressed
Example:
  - --tr-encoding $URL
---

# `--tr-encoding`

Request a compressed Transfer-Encoding response using one of the algorithms
curl supports, and uncompress the data while receiving it.

This method was once intended to be the way to do automatic data compression
for HTTP but for all practical purposes using Content-Encoding as done with
--compressed has superseded transfer encoding. The --tr-encoding option is
therefore often not be one you want.
