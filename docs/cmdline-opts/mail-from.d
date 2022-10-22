c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: mail-from
Arg: <address>
Help: Mail from this address
Protocols: SMTP
Added: 7.20.0
See-also: mail-rcpt mail-auth
Category: smtp
Example: --mail-from user@example.com -T mail smtp://example.com/
Multi: single
---
Specify a single address that the given mail should get sent from.
