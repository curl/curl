c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-clobber
Help: Do not overwrite files that already exist
Category: curl output
Added: 7.83.0
See-also: output remote-name
Example: --no-clobber --output local/dir/file $URL
Multi: boolean
---
When used in conjunction with the --output, --remote-header-name,
--remote-name, or --remote-name-all options, curl avoids overwriting files
that already exist. Instead, a dot and a number gets appended to the name
of the file that would be created, up to filename.100 after which it will not
create any file.

Note that this is the negated option name documented.  You can thus use
--clobber to enforce the clobbering, even if --remote-header-name or -J is
specified.
