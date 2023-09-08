c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tcp-nodelay
Help: Use the TCP_NODELAY option
Added: 7.11.2
Category: connection
Example: --tcp-nodelay $URL
See-also: no-buffer
Multi: boolean
---
Turn on the TCP_NODELAY option. See the *curl_easy_setopt(3)* man page for
details about this option.

curl sets this option by default and you need to explicitly switch it off if
you do not want it on (added in 7.50.2).
