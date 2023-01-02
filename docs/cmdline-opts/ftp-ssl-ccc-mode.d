c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-ssl-ccc-mode
Arg: <active/passive>
Help: Set CCC mode
Protocols: FTP
Added: 7.16.2
See-also: ftp-ssl-ccc
Category: ftp tls
Example: --ftp-ssl-ccc-mode active --ftp-ssl-ccc ftps://example.com/
Multi: boolean
---
Sets the CCC mode. The passive mode will not initiate the shutdown, but
instead wait for the server to do it, and will not reply to the shutdown from
the server. The active mode initiates the shutdown and waits for a reply from
the server.
