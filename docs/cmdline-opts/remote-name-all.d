c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: remote-name-all
Help: Use the remote file name for all URLs
Added: 7.19.0
Category: output
Example: --remote-name-all ftp://example.com/file1 ftp://example.com/file2
See-also: remote-name
---
This option changes the default action for all given URLs to be dealt with as
if --remote-name were used for each one. So if you want to disable that for a
specific URL after --remote-name-all has been used, you must use "-o -" or
--no-remote-name.
