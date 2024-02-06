---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-tlsuser
Arg: <name>
Help: TLS username for HTTPS proxy
Added: 7.52.0
Category: proxy tls auth
Multi: single
See-also:
  - proxy
  - proxy-tlspassword
Example:
  - --proxy-tlsuser smith -x https://proxy $URL
---

# `--proxy-tlsuser`

Same as --tlsuser but used in HTTPS proxy context.
