---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: remote-time
Short: R
Help: Set remote file's time on local output
Category: output
Added: 7.9
Multi: boolean
See-also:
  - remote-name
  - time-cond
Example:
  - --remote-time -o foo $URL
---

# `--remote-time`

Make curl attempt to figure out the timestamp of the remote file that is
getting downloaded, and if that is available make the local file get that same
timestamp.
