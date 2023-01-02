c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: a
Long: append
Help: Append to target file when uploading
Protocols: FTP SFTP
Category: ftp sftp
See-also: range continue-at
Example: --upload-file local --append ftp://example.com/
Added: 4.8
Multi: boolean
---
When used in an upload, this makes curl append to the target file instead of
overwriting it. If the remote file does not exist, it will be created. Note
that this flag is ignored by some SFTP servers (including OpenSSH).
