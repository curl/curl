c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tlspassword
Arg: <string>
Help: TLS password
Added: 7.21.4
Category: tls auth
Example: --tlspassword pwd --tlsuser user $URL
See-also: tlsuser
Multi: single
---
Set password for use with the TLS authentication method specified with
--tlsauthtype. Requires that --tlsuser also be set.

This option does not work with TLS 1.3.
