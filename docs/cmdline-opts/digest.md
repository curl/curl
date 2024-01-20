---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: digest
Help: Use HTTP Digest Authentication
Protocols: HTTP
Mutexed: basic ntlm negotiate
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

Enables HTTP Digest authentication. This is an authentication scheme that
prevents the password from being sent over the wire in clear text. Use this in
combination with the normal --user option to set user name and password.
