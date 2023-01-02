c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-tlspassword
Arg: <string>
Help: TLS password for HTTPS proxy
Added: 7.52.0
Category: proxy tls auth
Example: --proxy-tlspassword passwd -x https://proxy $URL
See-also: proxy proxy-tlsuser
Multi: single
---
Same as --tlspassword but used in HTTPS proxy context.
