c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: fail
Short: f
Protocols: HTTP
Help: Fail fast with no output on HTTP errors
See-also: fail-with-body
Category: important http
Example: --fail $URL
Mutexed: fail-with-body
Added: 4.0
---
Fail fast with no output at all on server errors. This is useful to enable
scripts and users to better deal with failed attempts. In normal cases when an
HTTP server fails to deliver a document, it returns an HTML document stating
so (which often also describes why and more). This flag will prevent curl from
outputting that and return error 22.

This method is not fail-safe and there are occasions where non-successful
response codes will slip through, especially when authentication is involved
(response codes 401 and 407).
