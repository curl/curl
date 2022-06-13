c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-pass
Arg: <phrase>
Help: Pass phrase for the private key for HTTPS proxy
Added: 7.52.0
Category: proxy tls auth
Example: --proxy-pass secret --proxy-key here -x https://proxy $URL
See-also: proxy proxy-key
---
Same as --pass but used in HTTPS proxy context.
