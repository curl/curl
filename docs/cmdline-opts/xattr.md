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

Store metadata in the extended file attributes.

When saving output to a file, tell curl to store file metadata in extended
file attributes. Currently, `curl` is stored in the `creator` attribute,
the URL is stored in the `xdg.origin.url` attribute, for HTTP, the content
type is stored in the `mime_type` attribute, and if set, the referrer URL in
`user.xdg.referrer.url`. If the file system does not support extended
attributes, a warning is issued.

Since curl 8.22.0 this option is also supported on Windows, where it creates
an Alternate Data Stream named `Zone.Identifier`. It contains an INI formatted
`ZoneTransfer` section, with values: `HostUrl`, `ReferrerUrl` (if set).
