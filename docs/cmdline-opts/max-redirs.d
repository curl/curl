c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: max-redirs
Arg: <num>
Help: Maximum number of redirects allowed
Protocols: HTTP
Category: http
Example: --max-redirs 3 --location $URL
Added: 7.5
See-also: location
Multi: single
---
Set maximum number of redirections to follow. When --location is used, to
prevent curl from following too many redirects, by default, the limit is
set to 50 redirects. Set this option to -1 to make it unlimited.
