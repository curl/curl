---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: happy-eyeballs-timeout-ms
Arg: <ms>
Help: Time for IPv6 before IPv4
Added: 7.59.0
Category: connection timeout
Multi: single
See-also:
  - max-time
  - connect-timeout
Example:
  - --happy-eyeballs-timeout-ms 500 $URL
---

# `--happy-eyeballs-timeout-ms`

Set the timeout for Happy Eyeballs.

Happy Eyeballs is an algorithm that attempts to connect to both IPv4 and IPv6
addresses for dual-stack hosts, giving IPv6 a head-start of the specified
number of milliseconds. If the IPv6 address cannot be connected to within that
time, then a connection attempt is made to the IPv4 address in parallel. The
first connection to be established is the one that is used.

The range of suggested useful values is limited. Happy Eyeballs RFC 6555 says
"It is RECOMMENDED that connection attempts be paced 150-250 ms apart to
balance human factors against network load." libcurl currently defaults to
200 ms. Firefox and Chrome currently default to 300 ms.
