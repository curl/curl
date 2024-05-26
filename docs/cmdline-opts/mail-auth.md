---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: mail-auth
Arg: <address>
Protocols: SMTP
Help: Originator address of the original email
Added: 7.25.0
Category: smtp
Multi: single
See-also:
  - mail-rcpt
  - mail-from
Example:
  - --mail-auth user@example.com -T mail smtp://example.com/
---

# `--mail-auth`

Specify a single address. This is used to specify the authentication address
(identity) of a submitted message that is being relayed to another server.
