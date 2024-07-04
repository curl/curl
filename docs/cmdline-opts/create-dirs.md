---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: create-dirs
Help: Create necessary local directory hierarchy
Category: output
Added: 7.10.3
Multi: boolean
See-also:
  - ftp-create-dirs
  - output-dir
Example:
  - --create-dirs --output local/dir/file $URL
---

# `--create-dirs`

When used in conjunction with the --output option, curl creates the necessary
local directory hierarchy as needed. This option creates the directories
mentioned with the --output option combined with the path possibly set with
--output-dir. If the combined output filename uses no directory, or if the
directories it mentions already exist, no directories are created.

Created directories are made with mode 0750 on unix style file systems.

To create remote directories when using FTP or SFTP, try --ftp-create-dirs.
