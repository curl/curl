---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: priority
Arg: <value>
Help: RFC 9218 request priority
Protocols: HTTP
Added: 8.24.0
Category: http
Multi: single
See-also:
  - http2
  - http3
Example:
  - --priority "u=1, i" $URL
  - --priority u=0 $URL
---

# `--priority`

Set the priority of the request as defined by RFC 9218, the HTTP priority
scheme. The value uses the syntax of the `Priority`
header field: `u=N` sets the urgency to N, a number from 0 (most urgent) to 7
(least urgent), and `i` (or `i=?1`) marks the response as incremental, one
the client can use as it arrives. Separate the two with a comma. Other
members and parameters of the dictionary are ignored, as the field syntax
asks. The keys are case sensitive and an empty value is an error.

curl sends the priority in a `Priority:` request header over HTTP/2 and
HTTP/3. A server that supports the scheme uses it to decide which responses
to send first when several are in progress over the same connection. The
option has no effect over HTTP/1.x.
