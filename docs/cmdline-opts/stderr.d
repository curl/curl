c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: stderr
Arg: <file>
Help: Where to redirect stderr
See-also: verbose silent
Category: verbose
Example: --stderr output.txt $URL
Added: 6.2
Multi: single
Scope: global
---
Redirect all writes to stderr to the specified file instead. If the file name
is a plain '-', it is instead written to stdout.
