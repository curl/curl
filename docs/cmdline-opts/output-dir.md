---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: output-dir
Arg: <dir>
Help: Directory to save files in
Added: 7.73.0
Category: output
Multi: single
See-also:
  - remote-name
  - remote-header-name
Example:
  - --output-dir "tmp" -O $URL
---

# `--output-dir`

Specify the directory in which files should be stored, when --remote-name or
--output are used.

The given output directory is used for all URLs and output options on the
command line, up until the first --next.

If the specified target directory does not exist, the operation fails unless
--create-dirs is also used.
