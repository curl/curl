---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: safe-auth
Help: Do not authenticate using a clear text password
Protocols: FTP HTTP IMAP LDAP POP3 SMTP
Added: 8.xx.x
Category: auth
Multi: boolean
See-also:
  - proxy-safe-auth
Example:
  - --user smith:secret --safe-auth http://example.com
---

# '--safe-auth'

Do not use an authentication mechanism that would transmit a clear text
password over a non-encrypted connection.

This option has precedence over other mechanism selection option.
