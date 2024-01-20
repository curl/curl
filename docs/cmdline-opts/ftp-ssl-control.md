---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-ssl-control
Help: Require SSL/TLS for FTP login, clear for transfer
Protocols: FTP
Added: 7.16.0
Category: ftp tls
Multi: boolean
See-also:
  - ssl
Example:
  - --ftp-ssl-control ftp://example.com
---

# `--ftp-ssl-control`

Require SSL/TLS for the FTP login, clear for transfer. Allows secure
authentication, but non-encrypted data transfers for efficiency. Fails the
transfer if the server does not support SSL/TLS.
