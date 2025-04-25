---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: follow
Help: Follow redirects per spec
Category: http
Added: 8.16.0
Multi: boolean
See-also:
  - request
  - location
Example:
  - -X POST --follow $URL
---

# `--follow`

Instructs curl to follow HTTP redirects and to do the custom request method
set with --request when following redirects as the HTTP specification says.

The method string set with --request is used in subsequent requests for the
status codes 307 or 308, but may be reset to GET for 301, 302 and 303.

This is subtly different than --location, as that option always set the custom
method in all subsequent requests independent of response code.
