---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: disallow-username-in-url
Help: Disallow username in URL
Added: 7.61.0
Category: fetch
Multi: boolean
See-also:
  - proto
Example:
  - --disallow-username-in-url $URL
---

# `--disallow-username-in-url`

Exit with error if passed a URL containing a username. Probably most useful
when the URL is being provided at runtime or similar.
