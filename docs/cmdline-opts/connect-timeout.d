Long: connect-timeout
Arg: <seconds>
Help: Maximum time allowed for connection
See-also: max-time
---
Maximum time in seconds that you allow curl's connection to take.  This only
limits the connection phase, so if curl connects within the given period it
will continue - if not it will exit.  Since version 7.32.0, this option
accepts decimal values.

If this option is used several times, the last one will be used.
