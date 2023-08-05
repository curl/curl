c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-account
Arg: <data>
Help: Account data string
Protocols: FTP
Added: 7.13.0
Category: ftp auth
Example: --ftp-account "mr.robot" ftp://example.com/
See-also: user
Multi: single
---
When an FTP server asks for "account data" after user name and password has
been provided, this data is sent off using the ACCT command.
