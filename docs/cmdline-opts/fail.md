---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: fail
Short: f
Protocols: HTTP
Help: Fail fast with no output on HTTP errors
Category: important http
Mutexed: fail-with-body
Added: 4.0
Multi: boolean
See-also:
  - fail-with-body
  - fail-early
Example:
  - --fail $URL
---

# `--fail`

Fail with error code 22 and with no response body output at all for HTTP
transfers returning HTTP response codes at 400 or greater.

In normal cases when an HTTP server fails to deliver a document, it returns a
body of text stating so (which often also describes why and more) and a 4xx
HTTP response code. This command line option prevents curl from outputting
that data and instead returns error 22 early. By default, curl does not
consider HTTP response codes to indicate failure.

To get both the error code and also save the content, use --fail-with-body
instead.

This method is not fail-safe and there are occasions where non-successful
response codes slip through, especially when authentication is involved
(response codes 401 and 407).
