---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: libfetch
Arg: <file>
Help: Generate libfetch code for this command line
Added: 7.16.1
Category: fetch global
Multi: single
Scope: global
See-also:
  - verbose
Example:
  - --libfetch client.c $URL
---

# `--libfetch`

Append this option to any ordinary fetch command line, and you get
libfetch-using C source code written to the file that does the equivalent of
what your command-line operation does.
