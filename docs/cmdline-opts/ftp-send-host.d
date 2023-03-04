c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-send-host
Help: Send HOST command
Protocols: FTP
Added: 8.1.0
Category: ftp
Example: --ftp-send-host ftp://example.com/
See-also: user
Multi: boolean
---
After control connection is established with an FTP server, hostname is sent
off using the HOST command to connect to the virtual host.
