---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: parallel-max
Arg: <num>
Help: Maximum concurrency for parallel transfers
Added: 7.66.0
Category: connection fetch global
Multi: single
Scope: global
See-also:
  - parallel
Example:
  - --parallel-max 100 -Z $URL ftp://example.com/
---

# `--parallel-max`

When asked to do parallel transfers, using --parallel, this option controls
the maximum amount of transfers to do simultaneously.

The default is 50. 300 is the largest supported value.
