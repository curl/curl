---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: disallow-username-in-url
Help: Disallow username in URL
Added: 7.61.0
Category: curl
Multi: boolean
See-also:
  - proto
Example:
  - --disallow-username-in-url $URL
---

# `--disallow-username-in-url`

This tells curl to exit if passed a URL containing a username. This is probably
most useful when the URL is being provided at runtime or similar.
