c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-cert
Arg: <cert[:passwd]>
Help: Set client certificate for proxy
Added: 7.52.0
Category: proxy tls
Example: --proxy-cert file -x https://proxy $URL
See-also: proxy-cert-type
Multi: single
---
Same as --cert but used in HTTPS proxy context.
