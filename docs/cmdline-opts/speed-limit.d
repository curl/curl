Long: speed-limit
Short: Y
Arg: <speed>
Help: Stop transfers slower than this
Category: connection
Example: --speed-limit 300 --speed-time 10 $URL
Added: 4.7
---
If a download is slower than this given speed (in bytes per second) for
speed-time seconds it gets aborted. speed-time is set with --speed-time and is
30 if not set.

If this option is used several times, the last one will be used.
