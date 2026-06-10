---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlsuser
Arg: <name>
Help: TLS username
Added: 7.21.4
Protocols: TLS
Category: tls auth
Multi: single
See-also:
  - tlspassword
Example:
  - --tlspassword pwd --tlsuser user $URL
---

# `--tlsuser`

Deprecated option. This has no functionality since 8.22.0.

Set username for use with the TLS authentication method specified with
--tlsauthtype. Requires that --tlspassword also is set.

This option does not work with TLS 1.3.
