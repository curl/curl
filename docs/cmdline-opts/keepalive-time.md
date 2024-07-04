---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: keepalive-time
Arg: <seconds>
Help: Interval time for keepalive probes
Added: 7.18.0
Category: connection timeout
Multi: single
See-also:
  - no-keepalive
  - keepalive-cnt
  - max-time
Example:
  - --keepalive-time 20 $URL
---

# `--keepalive-time`

Set the time a connection needs to remain idle before sending keepalive probes
and the time between individual keepalive probes. It is currently effective on
operating systems offering the `TCP_KEEPIDLE` and `TCP_KEEPINTVL` socket
options (meaning Linux, *BSD/macOS, Windows, Solaris, and recent AIX, HP-UX and more).
Keepalive is used by the TCP stack to detect broken networks on idle connections.
The number of missed keepalive probes before declaring the connection down is OS
dependent and is commonly 8 (*BSD/macOS/AIX), 9 (Linux/AIX) or 5/10 (Windows), and
this number can be changed by specifying the curl option `keepalive-cnt`.
Note that this option has no effect if --no-keepalive is used.

If unspecified, the option defaults to 60 seconds.
