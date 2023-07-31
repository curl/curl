c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-allow-unsafe-reneg
Help: Allow unsafe legacy renegotiation (OpenSSL)
Added: 8.3.0
Category: tls
Example: --ssl-allow-unsafe-reneg $URL
See-also: proxy-ssl-allow-unsafe-reneg insecure
Multi: boolean
---
This option tells curl built with OpenSSL to allow unsafe legacy renegotiation.
This option is only needed for OpenSSL 3 and later. Older versions of OpenSSL
and other SSL libraries may allow unsafe legacy renegotiation by default.

**WARNING**: this option loosens the SSL security, and by using this flag you
ask for exactly that.
