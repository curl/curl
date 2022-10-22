c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ssl-allow-beast
Help: Allow security flaw for interop for HTTPS proxy
Added: 7.52.0
Category: proxy tls
Example: --proxy-ssl-allow-beast -x https://proxy $URL
See-also: ssl-allow-beast proxy
Multi: boolean
---
Same as --ssl-allow-beast but used in HTTPS proxy context.
