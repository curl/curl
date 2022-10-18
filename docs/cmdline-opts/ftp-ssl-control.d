c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-ssl-control
Help: Require SSL/TLS for FTP login, clear for transfer
Protocols: FTP
Added: 7.16.0
Category: ftp tls
Example: --ftp-ssl-control ftp://example.com
See-also: ssl
Multi: boolean
---
Require SSL/TLS for the FTP login, clear for transfer.  Allows secure
authentication, but non-encrypted data transfers for efficiency.  Fails the
transfer if the server does not support SSL/TLS.
