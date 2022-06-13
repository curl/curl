c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: connect-timeout
Arg: <fractional seconds>
Help: Maximum time allowed for connection
See-also: max-time
Category: connection
Example: --connect-timeout 20 $URL
Example: --connect-timeout 3.14 $URL
Added: 7.7
---
Maximum time in seconds that you allow curl's connection to take.  This only
limits the connection phase, so if curl connects within the given period it
will continue - if not it will exit.  Since version 7.32.0, this option
accepts decimal values.

If this option is used several times, the last one will be used.
