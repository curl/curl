c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: compressed
Help: Request compressed response
Protocols: HTTP
Category: http
Example: --compressed $URL
See-also: compressed-ssh
Added: 7.10
Multi: boolean
---
Request a compressed response using one of the algorithms curl supports, and
automatically decompress the content. Headers are not modified.

If this option is used and the server sends an unsupported encoding, curl will
report an error. This is a request, not an order; the server may or may not
deliver data compressed.
