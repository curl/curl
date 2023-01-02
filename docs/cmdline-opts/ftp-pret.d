c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-pret
Help: Send PRET before PASV
Protocols: FTP
Added: 7.20.0
Category: ftp
Example: --ftp-pret ftp://example.com/
See-also: ftp-port ftp-pasv
Multi: boolean
---
Tell curl to send a PRET command before PASV (and EPSV). Certain FTP servers,
mainly drftpd, require this non-standard command for directory listings as
well as up and downloads in PASV mode.
