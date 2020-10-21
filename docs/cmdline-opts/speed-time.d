Long: speed-time
Short: y
Arg: <seconds>
Help: Trigger 'speed-limit' abort after this time
Category: connection
---
If a download is slower than speed-limit bytes per second during a speed-time
period, the download gets aborted. If speed-time is used, the default
speed-limit will be 1 unless set with --speed-limit.

This option controls transfers and thus will not affect slow connects etc. If
this is a concern for you, try the --connect-timeout option.

If this option is used several times, the last one will be used.
