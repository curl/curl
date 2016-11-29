Long: max-time
Short: m
Arg: <time>
Help: Maximum time allowed for the transfer
See-also: connect-timeout
---
Maximum time in seconds that you allow the whole operation to take.  This is
useful for preventing your batch jobs from hanging for hours due to slow
networks or links going down.  Since 7.32.0, this option accepts decimal
values, but the actual timeout will decrease in accuracy as the specified
timeout increases in decimal precision.

If this option is used several times, the last one will be used.
