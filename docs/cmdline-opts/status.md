---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: status
Help: Output only the HTTP status code
Protocols: HTTP HTTPS
Category: http
Added: 8.18.0
Multi: boolean
See-also:
  - head
  - location
  - show-headers
  - silent
  - verbose
Example:
  - --status $URL
---

# `--status`

Output only the HTTP status code from the response. This option suppresses all
other output including headers and response body, displaying only the numeric
HTTP status code (e.g., 200, 404, 500).

When combined with --silent, this produces clean output with only the status
code.

Combine with --location to get the status code for the redirect.
