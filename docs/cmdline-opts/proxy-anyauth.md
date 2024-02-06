---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-anyauth
Help: Pick any proxy authentication method
Added: 7.13.2
Category: proxy auth
Multi: mutex
See-also:
  - proxy
  - proxy-basic
  - proxy-digest
Example:
  - --proxy-anyauth --proxy-user user:passwd -x proxy $URL
---

# `--proxy-anyauth`

Tells curl to pick a suitable authentication method when communicating with
the given HTTP proxy. This might cause an extra request/response round-trip.
