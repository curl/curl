---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-negotiate
Help: HTTP Negotiate (SPNEGO) auth with the proxy
Added: 7.17.1
Category: proxy auth
Multi: mutex
See-also:
  - proxy-anyauth
  - proxy-basic
  - proxy-service-name
Example:
  - --proxy-negotiate --proxy-user user:passwd -x proxy $URL
---

# `--proxy-negotiate`

Use HTTP Negotiate (SPNEGO) authentication when communicating with the given
proxy. Use --negotiate for enabling HTTP Negotiate (SPNEGO) with a remote
host.
