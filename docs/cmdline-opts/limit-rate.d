Long: limit-rate
Arg: <speed>
Help: Limit transfer speed to RATE
---
Specify the maximum transfer rate you want curl to use - for both downloads
and uploads. This feature is useful if you have a limited pipe and you'd like
your transfer not to use your entire bandwidth. To make it slower than it
otherwise would be.

The given speed is measured in bytes/second, unless a suffix is appended.
Appending 'k' or 'K' will count the number as kilobytes, 'm' or M' makes it
megabytes, while 'g' or 'G' makes it gigabytes. Examples: 200K, 3m and 1G.

If you also use the --speed-limit option, that option will take precedence and
might cripple the rate-limiting slightly, to help keeping the speed-limit
logic working.

If this option is used several times, the last one will be used.
