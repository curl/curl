---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: hsts
Arg: <filename>
Protocols: HTTPS
Help: Enable HSTS with this cache file
Added: 7.74.0
Category: http
Multi: append
See-also:
  - proto
Example:
  - --hsts cache.txt $URL
---

# `--hsts`

Enable HSTS for the transfer. If the filename points to an existing HSTS cache
file, that is used. After a completed transfer, the cache is saved to the
filename again if it has been modified.

If curl is told to use HTTP:// for a transfer involving a hostname that exists
in the HSTS cache, it upgrades the transfer to use HTTPS. Each HSTS cache
entry has an individual lifetime after which the upgrade is no longer
performed.

Specify a "" filename (zero length) to avoid loading/saving and make curl just
handle HSTS in memory.

If this option is used several times, curl loads contents from all the
files but the last one is used for saving.
