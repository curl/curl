---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: Z
Long: parallel
Help: Perform transfers in parallel
Added: 7.66.0
Category: connection curl global
Multi: boolean
Scope: global
See-also:
  - next
  - verbose
  - parallel-max
  - parallel-immediate
  - fail-early
Example:
  - --parallel $URL -o file1 $URL -o file2
---

# `--parallel`

Make curl perform all transfers in parallel as compared to the regular serial
manner. Parallel transfer means that curl runs up to N concurrent transfers
simultaneously and if there are more than N transfers to handle, it starts new
ones when earlier transfers finish.

With parallel transfers, the progress meter output is different from when
doing serial transfers, as it then displays the transfer status for multiple
transfers in a single line.

The maximum amount of concurrent transfers is set with --parallel-max and it
defaults to 50.

When one or more parallel transfers fail, curl continues performing the
remaining transfers (unless --fail-early is used) and exits with the error
code of the first failed transfer. This differs from serial transfers, where
the exit code is determined by the last transfer unless --fail-early is used.
