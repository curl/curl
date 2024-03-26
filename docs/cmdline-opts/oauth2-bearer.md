---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: oauth2-bearer
Help: OAuth 2 Bearer Token
Arg: <token>
Protocols: IMAP LDAP POP3 SMTP HTTP
Category: auth
Added: 7.33.0
Multi: single
See-also:
  - basic
  - ntlm
  - digest
Example:
  - --oauth2-bearer "mF_9.B5f-4.1JqM" $URL
---

# `--oauth2-bearer`

Specify the Bearer Token for OAUTH 2.0 server authentication. The Bearer Token
is used in conjunction with the username which can be specified as part of the
--url or --user options.

The Bearer Token and username are formatted according to RFC 6750.
