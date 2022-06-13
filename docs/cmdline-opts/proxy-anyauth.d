c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-anyauth
Help: Pick any proxy authentication method
Added: 7.13.2
See-also: proxy proxy-basic proxy-digest
Category: proxy auth
Example: --proxy-anyauth --proxy-user user:passwd -x proxy $URL
---
Tells curl to pick a suitable authentication method when communicating with
the given HTTP proxy. This might cause an extra request/response round-trip.
