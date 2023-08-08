c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: styled-output
Help: Enable styled output for HTTP headers
Added: 7.61.0
Category: verbose
Example: --styled-output -I $URL
See-also: head verbose
Multi: boolean
Scope: global
---
Enables the automatic use of bold font styles when writing HTTP headers to the
terminal. Use --no-styled-output to switch them off.

Styled output requires a terminal that supports bold fonts. This feature is
not present on curl for Windows due to lack of this capability.
