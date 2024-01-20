---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: Z
Long: parallel
Help: Perform transfers in parallel
Added: 7.66.0
Category: connection curl
Multi: boolean
Scope: global
See-also:
  - next
  - verbose
Example:
  - --parallel $URL -o file1 $URL -o file2
---

# `--parallel`

Makes curl perform its transfers in parallel as compared to the regular serial
manner.
