c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: limit-rate
Arg: <speed>
Help: Limit transfer speed to RATE
Category: connection
Example: --limit-rate 100K $URL
Example: --limit-rate 1000 $URL
Example: --limit-rate 10M $URL
Added: 7.10
See-also: speed-limit speed-time
---
Specify the maximum transfer rate you want curl to use - for both downloads
and uploads. This feature is useful if you have a limited pipe and you would like
your transfer not to use your entire bandwidth. To make it slower than it
otherwise would be.

The given speed is measured in bytes/second, unless a suffix is appended.
Appending 'k' or 'K' will count the number as kilobytes, 'm' or 'M' makes it
megabytes, while 'g' or 'G' makes it gigabytes. The suffixes (k, M, G, T, P)
are 1024 based. For example 1k is 1024. Examples: 200K, 3m and 1G.

The rate limiting logic works on averaging the transfer speed to no more than
the set threshold over a period of multiple seconds.

If you also use the --speed-limit option, that option will take precedence and
might cripple the rate-limiting slightly, to help keeping the speed-limit
logic working.

If this option is used several times, the last one will be used.
