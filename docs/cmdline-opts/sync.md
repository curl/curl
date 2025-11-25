---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: sync
Help: Sync download with remote name/time/conditional
Category: output
Added: 8.12.0
Multi: boolean
See-also:
  - remote-name
  - remote-time
  - time-cond
Example:
  - --sync $URL/[1-100]
  - --sync $URL/{a,b,c}
  - --sync --output-dir "tmp" $URL/[1-100]
---

# `--sync`

Download files only if they return HTTP 200 OK status and are newer than the
local version (if it exists), using the remote filename, and set the local
file's modification time to match the remote file's Last-Modified header.

If the local file does not exist, it is downloaded (if HTTP 200 is returned).
If it exists and the remote file is newer (based on Last-Modified header), the
local file is updated. Otherwise, no download occurs.

Files that return HTTP errors (4xx, 5xx) or redirects (3xx) are automatically
skipped without creating local files.

The file is saved in the current working directory. Use --output-dir to save
in a different directory.
