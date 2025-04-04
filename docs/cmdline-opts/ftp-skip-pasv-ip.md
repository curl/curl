---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-skip-pasv-ip
Help: Skip the IP address for PASV
Protocols: FTP
Added: 7.15.0
Category: ftp
Multi: boolean
See-also:
  - ftp-pasv
Example:
  - --ftp-skip-pasv-ip ftp://example.com/
---

# `--ftp-skip-pasv-ip`

Do not use the IP address the server suggests in its response to curl's PASV
command when curl connects the data connection. Instead curl reuses the same
IP address it already uses for the control connection.

This option is enabled by default (added in 7.74.0).

This option has no effect if PORT, EPRT or EPSV is used instead of PASV.
