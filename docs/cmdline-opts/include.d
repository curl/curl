c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
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

Prior to 7.75.0 curl did not print the headers if --fail was used in
combination with this option and there was error reported by server.
