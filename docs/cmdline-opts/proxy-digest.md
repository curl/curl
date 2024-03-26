---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-digest
Help: Digest auth with the proxy
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

Use HTTP Digest authentication when communicating with the given proxy. Use
--digest for enabling HTTP Digest with a remote host.
