---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: max-redirs
Arg: <num>
Help: Maximum number of redirects allowed
Protocols: HTTP
Category: http
Added: 7.5
Multi: single
See-also:
  - location
Example:
  - --max-redirs 3 --location $URL
---

# `--max-redirs`

Set maximum number of redirections to follow. When --location is used, to
prevent curl from following too many redirects, by default, the limit is
set to 50 redirects. Set this option to -1 to make it unlimited.
