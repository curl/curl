c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: include
Short: i
Help: Include protocol response headers in the output
See-also: verbose
Category: important verbose
Example: -i $URL
Added: 4.8
Multi: boolean
---
Include the HTTP response headers in the output. The HTTP response headers can
include things like server name, cookies, date of the document, HTTP version
and more...

To view the request headers, consider the --verbose option.
