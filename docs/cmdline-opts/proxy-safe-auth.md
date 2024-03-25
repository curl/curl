---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-safe-auth
Help: Do not authenticate to proxy using a clear text password
Added: 8.xx.x
Category: proxy auth
Multi: boolean
See-also:
  - proxy-anyauth
  - safe-auth
Example:
  - --proxy-user smith:secret --proxy-safe-auth -x http://proxy $URL
---

# '--proxy-safe-auth'

Do not use a proxy authentication mechanism that would transmit a clear text
password over a non-encrypted connection.

This option has precedence over other mechanism selection option.
