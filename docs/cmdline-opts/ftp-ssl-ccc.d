c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-ssl-ccc
Help: Send CCC after authenticating
Protocols: FTP
See-also: ssl ftp-ssl-ccc-mode
Added: 7.16.1
Category: ftp tls
Example: --ftp-ssl-ccc ftps://example.com/
---
Use CCC (Clear Command Channel) Shuts down the SSL/TLS layer after
authenticating. The rest of the control channel communication will be
unencrypted. This allows NAT routers to follow the FTP transaction. The
default mode is passive.
