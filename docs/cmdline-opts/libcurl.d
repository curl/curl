c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: libcurl
Arg: <file>
Help: Dump libcurl equivalent code of this command line
Added: 7.16.1
Category: curl
Example: --libcurl client.c $URL
See-also: verbose
---
Append this option to any ordinary curl command line, and you will get
libcurl-using C source code written to the file that does the equivalent
of what your command-line operation does!

This option is global and does not need to be specified for each use of
--next.

If this option is used several times, the last given file name will be
used.
