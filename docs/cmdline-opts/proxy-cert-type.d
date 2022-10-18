c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-cert-type
Arg: <type>
Added: 7.52.0
Help: Client certificate type for HTTPS proxy
Category: proxy tls
Example: --proxy-cert-type PEM --proxy-cert file -x https://proxy $URL
See-also: proxy-cert
Multi: single
---
Same as --cert-type but used in HTTPS proxy context.
