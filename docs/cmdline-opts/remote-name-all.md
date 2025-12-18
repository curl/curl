---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: remote-name-all
Help: Use the remote filename for all URLs
Added: 7.19.0
Category: output
Multi: boolean
See-also:
  - remote-name
Example:
  - --remote-name-all ftp://example.com/file1 ftp://example.com/file2
---

# `--remote-name-all`

Change the default action for all given URLs to be dealt with as if
--remote-name were used for each one. If you want to disable that for a
specific URL after --remote-name-all has been used, you must use "-o -" or
--no-remote-name.
