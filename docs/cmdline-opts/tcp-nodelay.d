Long: tcp-nodelay
Help: Use the TCP_NODELAY option
Added: 7.11.2
Category: connection
Example: --tcp-nodelay $URL
See-also: no-buffer
---
Turn on the TCP_NODELAY option. See the *curl_easy_setopt(3)* man page for
details about this option.

Since 7.50.2, curl sets this option by default and you need to explicitly
switch it off if you do not want it on.
