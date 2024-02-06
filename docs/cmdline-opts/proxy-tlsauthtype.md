---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-tlsauthtype
Arg: <type>
Help: TLS authentication type for HTTPS proxy
Added: 7.52.0
Category: proxy tls auth
Multi: single
See-also:
  - proxy
  - proxy-tlsuser
Example:
  - --proxy-tlsauthtype SRP -x https://proxy $URL
---

# `--proxy-tlsauthtype`

Same as --tlsauthtype but used in HTTPS proxy context.
