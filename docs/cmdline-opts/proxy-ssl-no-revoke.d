c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ssl-no-revoke
Help: Disable cert revocation checks for HTTPS proxy (Schannel)
Added: 8.3.0
Category: tls
Example: --proxy-ssl-no-revoke -x https://proxy $URL
See-also: ssl-no-revoke proxy
Multi: boolean
---
Same as --ssl-no-revoke but used in HTTPS proxy context.
