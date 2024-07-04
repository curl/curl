---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: speed-time
Short: y
Arg: <seconds>
Help: Trigger 'speed-limit' abort after this time
Category: connection timeout
Added: 4.7
Multi: single
See-also:
  - speed-limit
  - limit-rate
Example:
  - --speed-limit 300 --speed-time 10 $URL
---

# `--speed-time`

If a transfer runs slower than speed-limit bytes per second during a
speed-time period, the transfer is aborted. If speed-time is used, the default
speed-limit is 1 unless set with --speed-limit.

This option controls transfers (in both directions) but does not affect slow
connects etc. If this is a concern for you, try the --connect-timeout option.
