c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: keepalive-time
Arg: <seconds>
Help: Interval time for keepalive probes
Added: 7.18.0
Category: connection
Example: --keepalive-time 20 $URL
See-also: no-keepalive max-time
---
This option sets the time a connection needs to remain idle before sending
keepalive probes and the time between individual keepalive probes. It is
currently effective on operating systems offering the TCP_KEEPIDLE and
TCP_KEEPINTVL socket options (meaning Linux, recent AIX, HP-UX and more).
Keepalives are used by the TCP stack to detect broken networks on idle
connections. The number of missed keepalive probes before declaring the
connection down is OS dependent and is commonly 9 or 10. This option has no
effect if --no-keepalive is used.

If this option is used several times, the last one will be used. If
unspecified, the option defaults to 60 seconds.
