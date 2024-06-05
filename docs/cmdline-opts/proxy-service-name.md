---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-service-name
Arg: <name>
Help: SPNEGO proxy service name
Added: 7.43.0
Category: proxy tls
Multi: single
See-also:
  - service-name
  - proxy
  - proxy-negotiate
Example:
  - --proxy-service-name "shrubbery" -x proxy $URL
---

# `--proxy-service-name`

Set the service name for SPNEGO when doing proxy authentication.
