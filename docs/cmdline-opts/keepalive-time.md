---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: keepalive-time
Arg: <seconds>
Help: Interval time for keepalive probes
Added: 7.18.0
Category: connection
Multi: single
See-also:
  - no-keepalive
  - max-time
Example:
  - --keepalive-time 20 $URL
---

# `--keepalive-time`

This option sets the time a connection needs to remain idle before sending
keepalive probes and the time between individual keepalive probes. It is
currently effective on operating systems offering the `TCP_KEEPIDLE` and
`TCP_KEEPINTVL` socket options (meaning Linux, recent AIX, HP-UX and more).
Keepalive is used by the TCP stack to detect broken networks on idle
connections. The number of missed keepalive probes before declaring the
connection down is OS dependent and is commonly 9 or 10. This option has no
effect if --no-keepalive is used.

If unspecified, the option defaults to 60 seconds.
