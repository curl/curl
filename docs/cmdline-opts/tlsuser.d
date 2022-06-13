c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlsuser
Arg: <name>
Help: TLS user name
Added: 7.21.4
Category: tls auth
Example: --tlspassword pwd --tlsuser user $URL
See-also: tlspassword
---
Set username for use with the TLS authentication method specified with
--tlsauthtype. Requires that --tlspassword also is set.

This option does not work with TLS 1.3.
