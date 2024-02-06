---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-ssl-ccc
Help: Send CCC after authenticating
Protocols: FTP
Added: 7.16.1
Category: ftp tls
Multi: boolean
See-also:
  - ssl
  - ftp-ssl-ccc-mode
Example:
  - --ftp-ssl-ccc ftps://example.com/
---

# `--ftp-ssl-ccc`

Use CCC (Clear Command Channel) Shuts down the SSL/TLS layer after
authenticating. The rest of the control channel communication is be
unencrypted. This allows NAT routers to follow the FTP transaction. The
default mode is passive.
