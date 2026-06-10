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
  - --proxy-tlsuser smith -x https://proxy.example $URL
---

# `--proxy-tlsuser`

Deprecated option. This has no functionality since 8.22.0.

Set username for use for HTTPS proxy with the TLS authentication method
specified with --proxy-tlsauthtype. Requires that --proxy-tlspassword also is
set.

This option does not work with TLS 1.3.
