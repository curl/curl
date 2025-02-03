---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: skip-existing
Help: Skip download if local file already exists
Category: fetch output
Added: 8.10.0
Multi: boolean
See-also:
  - output
  - remote-name
  - no-clobber
Example:
  - --skip-existing --output local/dir/file $URL
---

# `--skip-existing`

If there is a local file present when a download is requested, the operation
is skipped. Note that fetch cannot know if the local file was previously
downloaded fine, or if it is incomplete etc, it just knows if there is a
filename present in the file system or not and it skips the transfer if it is.
