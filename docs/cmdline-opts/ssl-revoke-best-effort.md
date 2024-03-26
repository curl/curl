---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-revoke-best-effort
Help: Ignore missing cert CRL dist points
Added: 7.70.0
Protocols: TLS
Category: tls
Multi: boolean
See-also:
  - crlfile
  - insecure
Example:
  - --ssl-revoke-best-effort $URL
---

# `--ssl-revoke-best-effort`

(Schannel) Ignore certificate revocation checks when they failed due to
missing/offline distribution points for the revocation check lists.
