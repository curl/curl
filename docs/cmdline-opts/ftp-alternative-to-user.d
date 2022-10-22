c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-alternative-to-user
Arg: <command>
Help: String to replace USER [name]
Protocols: FTP
Added: 7.15.5
Category: ftp
Example: --ftp-alternative-to-user "U53r" ftp://example.com
See-also: ftp-account user
Multi: single
---
If authenticating with the USER and PASS commands fails, send this command.
When connecting to Tumbleweed's Secure Transport server over FTPS using a
client certificate, using "SITE AUTH" will tell the server to retrieve the
username from the certificate.
