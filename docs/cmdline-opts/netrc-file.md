---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: netrc-file
Help: Specify FILE for netrc
Arg: <filename>
Added: 7.21.5
Mutexed: netrc
Category: curl
Multi: single
See-also:
  - netrc
  - user
  - config
Example:
  - --netrc-file netrc $URL
---

# `--netrc-file`

This option is similar to --netrc, except that you provide the path (absolute
or relative) to the netrc file that curl should use. You can only specify one
netrc file per invocation.

It abides by --netrc-optional if specified.
