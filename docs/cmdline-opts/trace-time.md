---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: trace-time
Help: Add time stamps to trace/verbose output
Added: 7.14.0
Category: verbose
Multi: boolean
Scope: global
See-also:
  - trace
  - verbose
Example:
  - --trace-time --trace-ascii output $URL
---

# `--trace-time`

Prepends a time stamp to each trace or verbose line that curl displays.
