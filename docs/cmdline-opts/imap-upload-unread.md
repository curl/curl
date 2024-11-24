---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: imap-upload-unread
Help: Specify that uploaded mail has not been read
Category: curl output
Added: 8.12.0
Multi: boolean
See-also:
  - upload-file
Example:
  - --imap-upload-unread --upload-file local/dir/file $URL
---

# `--imap-upload-unread`

When uploading mail via IMAP, this option causes curl to pass the server
the \\Seen flag, indicating that the mail has already been read. By default,
curl does not set this \\Seen flag, meaning that unless this option is set,
the server may assume uploaded mail is unread.
