---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: fail-on-status
Arg: <codes>
Protocols: HTTP
Help: Fail on specific HTTP status codes
Category: http
Added: 8.18.0
Multi: single
See-also:
  - fail
  - fail-with-body
  - fail-early
Example:
  - --fail-on-status 404 $URL
  - --fail-on-status 404,500-599 $URL
---

# `--fail-on-status`

Fail with error code 22 and with no response body output for HTTP transfers
returning specific HTTP status codes. This option allows you to specify exactly
which status codes should trigger failure.

The argument is a comma-separated list of HTTP status codes or ranges. For
example:

- `404` - Fail only on 404 Not Found
- `404,410` - Fail on 404 or 410
- `500-599` - Fail on any server error (500-599 inclusive)
- `404,500-599` - Fail on 404 or any server error

Ranges are inclusive on both ends. For example, `500-599` includes both 500
and 599.

When combined with --fail or --fail-with-body, the last option specified wins.
For example, using --fail followed by --fail-on-status deselects --fail in
favor of the more specific status code matching. Similarly, specifying
--fail-on-status followed by --fail-with-body will deselect --fail-on-status.

Note: The override pattern means only one failure mode is active at a time.
Cooperative behavior (e.g., failing on specific status codes AND saving the
response body) is not currently supported but may be added in a future version.

Valid status codes are 000-999. While standard HTTP status codes are in the
100-599 range, curl accepts any three-digit code for flexibility.
