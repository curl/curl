c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-key-type
Arg: <type>
Help: Private key file type for proxy
Added: 7.52.0
Category: proxy tls
Example: --proxy-key-type DER --proxy-key here -x https://proxy $URL
See-also: proxy-key proxy
Multi: single
---
Same as --key-type but used in HTTPS proxy context.
