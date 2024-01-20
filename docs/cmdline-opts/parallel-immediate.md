---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: parallel-immediate
Help: Do not wait for multiplexing (with --parallel)
Added: 7.68.0
Category: connection curl
Multi: boolean
Scope: global
See-also:
  - parallel
  - parallel-max
Example:
  - --parallel-immediate -Z $URL -o file1 $URL -o file2
---

# `--parallel-immediate`

When doing parallel transfers, this option instructs curl that it should
rather prefer opening up more connections in parallel at once rather than
waiting to see if new transfers can be added as multiplexed streams on another
connection.
