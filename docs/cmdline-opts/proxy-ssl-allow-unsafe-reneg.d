c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ssl-allow-unsafe-reneg
Help: Allow unsafe legacy renegotiation for HTTPS proxy (OpenSSL)
Added: 8.3.0
Category: proxy tls
Example: --proxy-ssl-allow-unsafe-reneg -x https://proxy $URL
See-also: ssl-allow-unsafe-reneg proxy
Multi: boolean
---
Same as --ssl-allow-unsafe-reneg but used in HTTPS proxy context.
