---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: libcurl
Arg: <file>
Help: Generate libcurl code for this command line
Added: 7.16.1
Category: curl
Multi: single
Scope: global
See-also:
  - verbose
Example:
  - --libcurl client.c $URL
---

# `--libcurl`

Append this option to any ordinary curl command line, and you get
libcurl-using C source code written to the file that does the equivalent of
what your command-line operation does!
