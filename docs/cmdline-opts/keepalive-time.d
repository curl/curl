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
TCP_KEEPINTVL socket options (meaning Linux, recent AIX, HP-UX and more). This
option has no effect if --no-keepalive is used.

If this option is used several times, the last one will be used. If
unspecified, the option defaults to 60 seconds.
