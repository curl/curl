---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-revoke-best-effort
Help: Ignore missing/offline cert CRL dist points (Schannel)
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

(Schannel) This option tells curl to ignore certificate revocation checks when
they failed due to missing/offline distribution points for the revocation check
lists.
