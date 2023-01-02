c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: crlf
Help: Convert LF to CRLF in upload
Protocols: FTP SMTP
Category: ftp smtp
Example: --crlf -T file ftp://example.com/
Added: 5.7
See-also: use-ascii
Multi: boolean
---
Convert LF to CRLF in upload. Useful for MVS (OS/390).

(SMTP added in 7.40.0)
