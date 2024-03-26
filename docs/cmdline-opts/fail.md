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

Fail fast with no output at all on server errors. This is useful to enable
scripts and users to better deal with failed attempts. In normal cases when an
HTTP server fails to deliver a document, it returns an HTML document stating
so (which often also describes why and more). This command line option
prevents curl from outputting that and return error 22.

This method is not fail-safe and there are occasions where non-successful
response codes slip through, especially when authentication is involved
(response codes 401 and 407).
