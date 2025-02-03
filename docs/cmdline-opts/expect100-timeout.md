---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: expect100-timeout
Arg: <seconds>
Help: How long to wait for 100-continue
Protocols: HTTP
Added: 7.47.0
Category: http timeout
Multi: single
See-also:
  - connect-timeout
Example:
  - --expect100-timeout 2.5 -T file $URL
---

# `--expect100-timeout`

Maximum time in seconds that you allow fetch to wait for a 100-continue
response when fetch emits an Expects: 100-continue header in its request. By
default fetch waits one second. This option accepts decimal values. When fetch
stops waiting, it continues as if a response was received.

The decimal value needs to be provided using a dot (`.`) as decimal separator -
not the local version even if it might be using another separator.
