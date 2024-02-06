---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: crlf
Help: Convert LF to CRLF in upload
Protocols: FTP SMTP
Category: ftp smtp
Added: 5.7
Multi: boolean
See-also:
  - use-ascii
Example:
  - --crlf -T file ftp://example.com/
---

# `--crlf`

Convert line feeds to carriage return plus line feeds in upload. Useful for
**MVS (OS/390)**.

(SMTP added in 7.40.0)
