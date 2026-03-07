---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: create-file-mode
Arg: <mode>
Help: File mode for created files
Protocols: SFTP SCP FILE
Category: sftp scp file upload
Added: 7.75.0
Multi: single
See-also:
  - ftp-create-dirs
Example:
  - --create-file-mode 0777 -T localfile sftp://example.com/new
---

# `--create-file-mode`

When curl is used to create files remotely using one of the supported
protocols, this option allows the user to set which 'mode' to set on the file
at creation time, instead of the default 0644.

This option takes an octal number as argument.
