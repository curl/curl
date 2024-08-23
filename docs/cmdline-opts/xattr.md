---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: xattr
Help: Store metadata in extended file attributes
Category: output
Added: 7.21.3
Multi: boolean
See-also:
  - remote-time
  - write-out
  - verbose
Example:
  - --xattr -o storage $URL
---

# `--xattr`

When saving output to a file, tell curl to store file metadata in extended
file attributes. Currently, the URL is stored in the `xdg.origin.url`
attribute and, for HTTP, the content type is stored in the `mime_type`
attribute. If the file system does not support extended attributes, a warning
is issued.
