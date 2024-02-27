---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: mail-rcpt
Arg: <address>
Help: Mail to this address
Protocols: SMTP
Added: 7.20.0
Category: smtp
Multi: append
See-also:
  - mail-rcpt-allowfails
Example:
  - --mail-rcpt user@example.net smtp://example.com
---

# `--mail-rcpt`

Specify a single email address, username or mailing list name. Repeat this
option several times to send to multiple recipients.

When performing an address verification (**VRFY** command), the recipient
should be specified as the username or username and domain (as per Section 3.5
of RFC 5321). (Added in 7.34.0)

When performing a mailing list expand (EXPN command), the recipient should be
specified using the mailing list name, such as "Friends" or "London-Office".
(Added in 7.34.0)
