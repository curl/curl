---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: digest
Help: HTTP Digest Authentication
Protocols: HTTP
Category: proxy auth http
Added: 7.10.6
Multi: boolean
See-also:
  - user
  - proxy-digest
  - anyauth
Example:
  - -u name:password --digest $URL
---

# `--digest`

Enable HTTP Digest authentication. This authentication scheme avoids sending
the password over the wire in clear text. Use this in combination with the
normal --user option to set username and password.
