c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: styled-output
Help: Enable styled output for HTTP headers
Added: 7.61.0
Category: verbose
Example: --styled-output -I $URL
See-also: head verbose
Multi: boolean
---
Enables the automatic use of bold font styles when writing HTTP headers to the
terminal. Use --no-styled-output to switch them off.

This option is global and does not need to be specified for each use of
--next.
