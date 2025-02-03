---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: proto-redir
Arg: <protocols>
Help: Enable/disable PROTOCOLS on redirect
Added: 7.20.2
Category: connection fetch
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

    fetch --proto-redir -all,http,https http://example.com

By default fetch only allows HTTP, HTTPS, FTP and FTPS on redirects
(added in 7.65.2). Specifying *all* or *+all* enables all protocols on
redirects, which is not good for security.
