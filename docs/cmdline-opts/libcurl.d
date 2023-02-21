c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: libcurl
Arg: <file>
Help: Dump libcurl equivalent code of this command line
Added: 7.16.1
Category: curl
Example: --libcurl client.c $URL
See-also: verbose
Multi: single
Scope: global
---
Append this option to any ordinary curl command line, and you will get
libcurl-using C source code written to the file that does the equivalent
of what your command-line operation does!
