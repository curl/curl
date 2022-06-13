c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: compressed-ssh
Help: Enable SSH compression
Protocols: SCP SFTP
Added: 7.56.0
Category: scp ssh
See-also: compressed
Example: --compressed-ssh sftp://example.com/
---
Enables built-in SSH compression.
This is a request, not an order; the server may or may not do it.
