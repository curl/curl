c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-ciphers
Arg: <list>
Help: SSL ciphers to use for proxy
Added: 7.52.0
Category: proxy tls
Example: --proxy-ciphers ECDHE-ECDSA-AES256-CCM8 -x https://proxy $URL
See-also: ciphers curves proxy
Multi: single
---
Same as --ciphers but used in HTTPS proxy context.
