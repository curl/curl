c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: netrc-file
Help: Specify FILE for netrc
Arg: <filename>
Added: 7.21.5
Mutexed: netrc
Category: curl
Example: --netrc-file netrc $URL
See-also: netrc user config
Multi: single
---
This option is similar to --netrc, except that you provide the path (absolute
or relative) to the netrc file that curl should use. You can only specify one
netrc file per invocation.

It will abide by --netrc-optional if specified.
