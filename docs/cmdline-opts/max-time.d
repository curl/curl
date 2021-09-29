Long: max-time
Short: m
Arg: <fractional seconds>
Help: Maximum time allowed for transfer
See-also: connect-timeout
Category: connection
Example: --max-time 10 $URL
Example: --max-time 2.92 $URL
Added: 4.0
---
Maximum time in seconds that you allow the whole operation to take.  This is
useful for preventing your batch jobs from hanging for hours due to slow
networks or links going down.  Since 7.32.0, this option accepts decimal
values, but the actual timeout will decrease in accuracy as the specified
timeout increases in decimal precision.

If this option is used several times, the last one will be used.
