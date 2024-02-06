---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: silent
Short: s
Help: Silent mode
Category: important verbose
Added: 4.0
Multi: boolean
See-also:
  - verbose
  - stderr
  - no-progress-meter
Example:
  - -s $URL
---

# `--silent`

Silent or quiet mode. Do not show progress meter or error messages. Makes Curl
mute. It still outputs the data you ask for, potentially even to the
terminal/stdout unless you redirect it.

Use --show-error in addition to this option to disable progress meter but
still show error messages.
