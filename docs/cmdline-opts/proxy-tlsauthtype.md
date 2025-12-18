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
  - proxy-tlspassword
Example:
  - --proxy-tlsauthtype SRP -x https://proxy $URL
---

# `--proxy-tlsauthtype`

Set TLS authentication type with HTTPS proxy. The only supported option is
`SRP`, for TLS-SRP (RFC 5054). This option works only if the underlying
libcurl is built with TLS-SRP support.

Equivalent to --tlsauthtype but used in HTTPS proxy context.
