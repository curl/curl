---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proto-redir
Arg: <protocols>
Help: Enable/disable PROTOCOLS on redirect
Added: 7.21.0
Category: connection curl
Multi: single
See-also:
  - proto
Example:
  - --proto-redir =http,https $URL
---

# `--proto-redir`

Limit what protocols to allow on redirects. Protocols denied by --proto are
not overridden by this option. See --proto for how protocols are represented.

Example, allow only HTTP and HTTPS on redirect:

    curl --proto-redir -all,http,https http://example.com

By default curl only allows HTTP, HTTPS, FTP and FTPS on redirects
(added in 7.65.2). Specifying *all* or *+all* enables all protocols on
redirects, which is not good for security.
