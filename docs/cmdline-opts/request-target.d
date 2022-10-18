c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: request-target
Arg: <path>
Help: Specify the target for this request
Protocols: HTTP
Added: 7.55.0
Category: http
Example: --request-target "*" -X OPTIONS $URL
See-also: request
Multi: single
---
Tells curl to use an alternative "target" (path) instead of using the path as
provided in the URL. Particularly useful when wanting to issue HTTP requests
without leading slash or other data that does not follow the regular URL
pattern, like "OPTIONS *".
