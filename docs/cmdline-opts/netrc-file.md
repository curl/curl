---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: netrc-file
Help: Specify FILE for netrc
Arg: <filename>
Added: 7.21.5
Mutexed: netrc
Category: auth
Multi: single
See-also:
  - netrc
  - user
  - config
Example:
  - --netrc-file netrc $URL
---

# `--netrc-file`

Set the netrc file to use. Similar to --netrc, except that you also provide
the path (absolute or relative).

It abides by --netrc-optional if specified.
