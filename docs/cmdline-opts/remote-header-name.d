c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: remote-header-name
Short: J
Protocols: HTTP
Help: Use the header-provided filename
Category: output
Example: -OJ https://example.com/file
Added: 7.20.0
See-also: remote-name
---
This option tells the --remote-name option to use the server-specified
Content-Disposition filename instead of extracting a filename from the URL. If
the server-provided file name contains a path, that will be stripped off
before the file name is used.

The file is saved in the current directory, or in the directory specified with
--output-dir.

If the server specifies a file name and a file with that name already exists
in the destination directory, it will not be overwritten and an error will
occur. If the server does not specify a file name then this option has no
effect.

There's no attempt to decode %-sequences (yet) in the provided file name, so
this option may provide you with rather unexpected file names.

**WARNING**: Exercise judicious use of this option, especially on Windows. A
rogue server could send you the name of a DLL or other file that could be
loaded automatically by Windows or some third party software.
