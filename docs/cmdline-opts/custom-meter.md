---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: custom-meter
Arg: <seconds>
Help: Custom progress meter update interval
Category: verbose global
Added: 8.18.0
Multi: boolean
Scope: global
See-also:
  - progress-bar
  - no-progress-meter
Example:
  - --custom-meter 10 -O $URL
  - --custom-meter 0.5 -O $URL
---

# `--custom-meter`

Set a custom update interval for the progress meter display. The argument
specifies the number of seconds between updates and accepts decimal values
(e.g., 0.5 for half a second, 2.5 for two and a half seconds).

If the specified interval is 0, progress updates occur as frequently as
possible (subject to system performance).
