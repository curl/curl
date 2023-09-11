c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: decode-remote-name
Help: URL-decode the server-sent filename when saving files locally
Category: output
Example: -O --decode-remote-name https://example.com/some%20filename.txt
Example: -OJ --decode-remote-name https://example.com/some%20filename.txt
See-also: remote-name-all output-dir remote-header-name
Multi: single
Added: 9.9
---
When writing output to local files using the -J, --remote-header-name and/or
-O, --remote-name options, this option will URL-decode filenames before
saving locally.

When used with -J, --remote-header-name, the Content-Disposition header's
'filename*' field will be URL-decoded and used if present. If no 'filename*'
field is present, the 'filename' field will be used without URL-decoding.
If no 'filename*' or 'filename' field is present in the Content-Disposition
header, or if this header is missing, the filename in the URL will be decoded
and used.

When used with -O, --remote-name, the filename in the URL will be decoded and
used.

If the server-provided file name contains a path, that will be stripped off
before the file name is used.

This option applies to all URLs on the command line.
