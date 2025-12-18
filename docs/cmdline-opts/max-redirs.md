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
  - follow
Example:
  - --max-redirs 3 --location $URL
---

# `--max-redirs`

Set the maximum number of redirections to follow. When --location or --follow
are used, this option prevents curl from following too many redirects. By
default the limit is set to 50 redirects. Set this option to -1 to make it
unlimited.
