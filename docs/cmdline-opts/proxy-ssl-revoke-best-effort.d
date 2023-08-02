c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ssl-revoke-best-effort
Help: Ignore missing/offline cert CRL dist points for HTTPS proxy (Schannel)
Added: 8.3.0
Category: tls
Example: --proxy-ssl-revoke-best-effort -x https://proxy $URL
See-also: ssl-revoke-best-effort proxy
Multi: boolean
---
Same as --ssl-revoke-best-effort but used in HTTPS proxy context.
