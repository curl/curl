c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: max-redirs
Arg: <num>
Help: Maximum number of redirects allowed
Protocols: HTTP
Category: http
Example: --max-redirs 3 --location $URL
Added: 7.5
See-also: location
---
Set maximum number of redirections to follow. When --location is used, to
prevent curl from following too many redirects, by default, the limit is
set to 50 redirects. Set this option to -1 to make it unlimited.

If this option is used several times, the last one will be used.
