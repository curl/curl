---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: C
Long: continue-at
Arg: <offset>
Help: Resumed transfer offset
Category: connection
Added: 4.8
Multi: single
See-also:
  - range
Example:
  - -C - $URL
  - -C 400 $URL
---

# `--continue-at`

Resume a previous transfer from the given byte offset. The given offset is the
exact number of bytes that are skipped, counting from the beginning of the
source file before it is transferred to the destination. If used with uploads,
the FTP server command SIZE is not used by curl.

Use "-C -" to instruct curl to automatically find out where/how to resume the
transfer. It then uses the given output/input files to figure that out.

When using this option for HTTP uploads using POST or PUT, functionality is
not guaranteed. The HTTP protocol has no standard interoperable resume upload
and curl uses a set of headers for this purpose that once proved working for
some servers and have been left for those who find that useful.

This command line option is mutually exclusive with --range: you can only use
one of them for a single transfer.

The --no-clobber and --remove-on-error options cannot be used together with
--continue-at.
