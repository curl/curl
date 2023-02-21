c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: Z
Long: parallel
Help: Perform transfers in parallel
Added: 7.66.0
Category: connection curl
Example: --parallel $URL -o file1 $URL -o file2
See-also: next verbose
Multi: boolean
Scope: global
---
Makes curl perform its transfers in parallel as compared to the regular serial
manner.
