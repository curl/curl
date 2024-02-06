---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-keepalive
Help: Disable TCP keepalive on the connection
Category: connection
Added: 7.18.0
Multi: boolean
See-also:
  - keepalive-time
Example:
  - --no-keepalive $URL
---

# `--no-keepalive`

Disables the use of keepalive messages on the TCP connection. curl otherwise
enables them by default.

Note that this is the negated option name documented. You can thus use
--keepalive to enforce keepalive.
