---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: speed-limit
Short: Y
Arg: <speed>
Help: Stop transfers slower than this
Category: connection
Added: 4.7
Multi: single
See-also:
  - speed-time
  - limit-rate
  - max-time
Example:
  - --speed-limit 300 --speed-time 10 $URL
---

# `--speed-limit`

If a transfer is slower than this set speed (in bytes per second) for a given
number of seconds, it gets aborted. The time period is set with --speed-time
and is 30 seconds by default.
