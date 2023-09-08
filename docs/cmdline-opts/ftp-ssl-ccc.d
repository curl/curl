c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-ssl-ccc
Help: Send CCC after authenticating
Protocols: FTP
See-also: ssl ftp-ssl-ccc-mode
Added: 7.16.1
Category: ftp tls
Example: --ftp-ssl-ccc ftps://example.com/
Multi: boolean
---
Use CCC (Clear Command Channel) Shuts down the SSL/TLS layer after
authenticating. The rest of the control channel communication is be
unencrypted. This allows NAT routers to follow the FTP transaction. The
default mode is passive.
