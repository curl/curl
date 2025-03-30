---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ftp-ssl-ccc-mode
Arg: <active/passive>
Help: Set CCC mode
Protocols: FTP
Added: 7.16.2
Category: ftp tls
Multi: boolean
See-also:
  - ftp-ssl-ccc
Example:
  - --ftp-ssl-ccc-mode active --ftp-ssl-ccc ftps://example.com/
---

# `--ftp-ssl-ccc-mode`

Set the CCC mode. The passive mode does not initiate the shutdown, but instead
waits for the server to do it, and does not reply to the shutdown from the
server. The active mode initiates the shutdown and waits for a reply from the
server.
