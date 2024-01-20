---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: netrc-optional
Help: Use either .netrc or URL
Mutexed: netrc
Category: curl
Added: 7.9.8
Multi: boolean
See-also:
  - netrc-file
Example:
  - --netrc-optional $URL
---

# `--netrc-optional`

Similar to --netrc, but this option makes the .netrc usage **optional**
and not mandatory as the --netrc option does.
