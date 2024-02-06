---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-digest
Help: Use Digest authentication on the proxy
Category: proxy tls
Added: 7.12.0
Multi: mutex
See-also:
  - proxy
  - proxy-anyauth
  - proxy-basic
Example:
  - --proxy-digest --proxy-user user:passwd -x proxy $URL
---

# `--proxy-digest`

Tells curl to use HTTP Digest authentication when communicating with the given
proxy. Use --digest for enabling HTTP Digest with a remote host.
