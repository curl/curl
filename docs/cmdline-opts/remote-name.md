---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: remote-name
Short: O
Help: Write output to file named as remote file
Category: important output
Added: 4.0
Multi: per-URL
See-also:
  - remote-name-all
  - output-dir
  - remote-header-name
Example:
  - -O https://example.com/filename
  - -O https://example.com/filename -O https://example.com/file2
---

# `--remote-name`

Write output to a local file named like the remote file we get. (Only the file
part of the remote file is used, the path is cut off.)

The file is saved in the current working directory. If you want the file saved
in a different directory, make sure you change the current working directory
before invoking curl with this option or use --output-dir.

The remote filename to use for saving is extracted from the given URL, nothing
else, and if it already exists it is overwritten. If you want the server to be
able to choose the filename refer to --remote-header-name which can be used in
addition to this option. If the server chooses a filename and that name
already exists it is not overwritten.

There is no URL decoding done on the filename. If it has %20 or other URL
encoded parts of the name, they end up as-is as filename.

You may use this option as many times as the number of URLs you have.
