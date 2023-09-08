c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: C
Long: continue-at
Arg: <offset>
Help: Resumed transfer offset
See-also: range
Category: connection
Example: -C - $URL
Example: -C 400 $URL
Added: 4.8
Multi: single
---
Continue/Resume a previous file transfer at the given offset. The given offset
is the exact number of bytes that are skipped, counting from the beginning
of the source file before it is transferred to the destination. If used with
uploads, the FTP server command SIZE is not used by curl.

Use "-C -" to tell curl to automatically find out where/how to resume the
transfer. It then uses the given output/input files to figure that out.
