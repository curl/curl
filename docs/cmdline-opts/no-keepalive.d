Long: no-keepalive
Help: Disable TCP keepalive on the connection
Category: connection
Example: --no-keepalive $URL
Added: 7.18.0
See-also: keepalive-time
---
Disables the use of keepalive messages on the TCP connection. curl otherwise
enables them by default.

Note that this is the negated option name documented. You can thus use
--keepalive to enforce keepalive.
