c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: netrc-optional
Help: Use either .netrc or URL
Mutexed: netrc
See-also: netrc-file
Category: curl
Example: --netrc-optional $URL
Added: 7.9.8
---
Similar to --netrc, but this option makes the .netrc usage **optional**
and not mandatory as the --netrc option does.
