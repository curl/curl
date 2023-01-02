c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: output-dir
Arg: <dir>
Help: Directory to save files in
Added: 7.73.0
See-also: remote-name remote-header-name
Category: curl
Example: --output-dir "tmp" -O $URL
Multi: single
---
This option specifies the directory in which files should be stored, when
--remote-name or --output are used.

The given output directory is used for all URLs and output options on the
command line, up until the first --next.

If the specified target directory does not exist, the operation will fail
unless --create-dirs is also used.
