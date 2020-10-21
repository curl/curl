Long: tcp-nodelay
Help: Use the TCP_NODELAY option
Added: 7.11.2
Category: connection
---
Turn on the TCP_NODELAY option. See the \fIcurl_easy_setopt(3)\fP man page for
details about this option.

Since 7.50.2, curl sets this option by default and you need to explicitly
switch it off if you don't want it on.
