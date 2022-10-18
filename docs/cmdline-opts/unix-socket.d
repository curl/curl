c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: unix-socket
Arg: <path>
Help: Connect through this Unix domain socket
Added: 7.40.0
Protocols: HTTP
Category: connection
See-also: abstract-unix-socket
Example: --unix-socket socket-path $URL
Multi: single
---
Connect through this Unix domain socket, instead of using the network.
