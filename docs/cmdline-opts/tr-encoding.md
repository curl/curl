---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
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
fetch supports, and uncompress the data while receiving it.
