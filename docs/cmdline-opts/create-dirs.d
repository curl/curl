c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: create-dirs
Help: Create necessary local directory hierarchy
Category: curl
Example: --create-dirs --output local/dir/file $URL
Added: 7.10.3
See-also: ftp-create-dirs output-dir
Multi: boolean
---
When used in conjunction with the --output option, curl creates the necessary
local directory hierarchy as needed. This option creates the directories
mentioned with the --output option, nothing else. If the --output file name
uses no directory, or if the directories it mentions already exist, no
directories are created.

Created directories are made with mode 0750 on unix style file systems.

To create remote directories when using FTP or SFTP, try --ftp-create-dirs.
