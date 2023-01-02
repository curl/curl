c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dump-header
Short: D
Arg: <filename>
Help: Write the received headers to <filename>
Protocols: HTTP FTP
See-also: output
Category: http ftp
Example: --dump-header store.txt $URL
Added: 5.7
Multi: single
---
Write the received protocol headers to the specified file. If no headers are
received, the use of this option will create an empty file.

When used in FTP, the FTP server response lines are considered being "headers"
and thus are saved there.

Having multiple transfers in one set of operations (i.e. the URLs in one
--next clause), will append them to the same file, separated by a blank line.
