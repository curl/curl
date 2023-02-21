c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: show-error
Short: S
Help: Show error even when -s is used
See-also: no-progress-meter
Category: curl
Example: --show-error --silent $URL
Added: 5.9
Multi: boolean
Scope: global
---
When used with --silent, it makes curl show an error message if it fails.
