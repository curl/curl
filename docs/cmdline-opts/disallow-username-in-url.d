c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: disallow-username-in-url
Help: Disallow username in URL
Added: 7.61.0
See-also: proto
Category: curl
Example: --disallow-username-in-url $URL
Multi: boolean
---
This tells curl to exit if passed a URL containing a username. This is probably
most useful when the URL is being provided at runtime or similar.
