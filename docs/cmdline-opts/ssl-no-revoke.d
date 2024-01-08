c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-no-revoke
Help: Disable cert revocation checks (Schannel)
Added: 7.44.0
Protocols: TLS
Category: tls
Example: --ssl-no-revoke $URL
See-also: crlfile
Multi: boolean
---
(Schannel) This option tells curl to disable certificate revocation checks.
WARNING: this option loosens the SSL security, and by using this flag you ask
for exactly that.
