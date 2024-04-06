---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-basic
Help: Use Basic authentication on the proxy
Category: proxy auth
Added: 7.12.0
Multi: mutex
See-also:
  - proxy
  - proxy-anyauth
  - proxy-digest
Example:
  - --proxy-basic --proxy-user user:passwd -x proxy $URL
---

# `--proxy-basic`

Use HTTP Basic authentication when communicating with the given proxy. Use
--basic for enabling HTTP Basic with a remote host. Basic is the default
authentication method curl uses with proxies.
