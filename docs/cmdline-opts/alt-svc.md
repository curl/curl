---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: alt-svc
Arg: <filename>
Protocols: HTTPS
Help: Enable alt-svc with this cache file
Added: 7.64.1
Category: http
Multi: append
See-also:
  - resolve
  - connect-to
Example:
  - --alt-svc svc.txt $URL
---

# `--alt-svc`

Enable the alt-svc parser. If the filename points to an existing alt-svc cache
file, that gets used. After a completed transfer, the cache is saved to the
filename again if it has been modified.

Specify a "" filename (zero length) to avoid loading/saving and make curl just
handle the cache in memory.

If this option is used several times, curl loads contents from all the
files but the last one is used for saving.
