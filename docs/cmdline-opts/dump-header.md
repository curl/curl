---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dump-header
Short: D
Arg: <filename>
Help: Write the received headers to <filename>
Protocols: HTTP FTP
Category: http ftp
Added: 5.7
Multi: single
See-also:
  - output
Example:
  - --dump-header store.txt $URL
  - --dump-header - $URL -o save
---

# `--dump-header`

Write the received protocol headers to the specified file. If no headers are
received, the use of this option creates an empty file. Specify `-` as file
name (a single minus) to have it written to stdout.

When used in FTP, the FTP server response lines are considered being "headers"
and thus are saved there.

Having multiple transfers in one set of operations (i.e. the URLs in one
--next clause), appends them to the same file, separated by a blank line.
