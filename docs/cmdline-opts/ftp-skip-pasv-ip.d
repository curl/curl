c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-skip-pasv-ip
Help: Skip the IP address for PASV
Protocols: FTP
Added: 7.14.2
See-also: ftp-pasv
Category: ftp
Example: --ftp-skip-pasv-ip ftp://example.com/
Multi: boolean
---
Tell curl to not use the IP address the server suggests in its response to
curl's PASV command when curl connects the data connection. Instead curl
reuses the same IP address it already uses for the control connection.

This option is enabled by default (added in 7.74.0).

This option has no effect if PORT, EPRT or EPSV is used instead of PASV.
