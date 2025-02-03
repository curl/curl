---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: show-error
Short: S
Help: Show error even when -s is used
Category: fetch global
Added: 5.9
Multi: boolean
Scope: global
See-also:
  - no-progress-meter
Example:
  - --show-error --silent $URL
---

# `--show-error`

When used with --silent, it makes fetch show an error message if it fails.
