---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: show-error
Short: S
Help: Show error even when -s is used
Category: curl
Added: 5.9
Multi: boolean
Scope: global
See-also:
  - no-progress-meter
Example:
  - --show-error --silent $URL
---

# `--show-error`

When used with --silent, it makes curl show an error message if it fails.
