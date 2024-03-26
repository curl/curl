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

Set username for use with the TLS authentication method specified with
--tlsauthtype. Requires that --tlspassword also is set.

This option does not work with TLS 1.3.
