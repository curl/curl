c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: xattr
Help: Store metadata in extended file attributes
Category: misc
Example: --xattr -o storage $URL
Added: 7.21.3
See-also: remote-time write-out verbose
Multi: boolean
---
When saving output to a file, this option tells curl to store certain file
metadata in extended file attributes. Currently, the URL is stored in the
xdg.origin.url attribute and, for HTTP, the content type is stored in
the mime_type attribute. If the file system does not support extended
attributes, a warning is issued.
