c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: abstract-unix-socket
Arg: <path>
Help: Connect via abstract Unix domain socket
Added: 7.53.0
Protocols: HTTP
Category: connection
See-also: unix-socket
Example: --abstract-unix-socket socketpath $URL
Multi: single
---
Connect through an abstract Unix domain socket, instead of using the network.
Note: netstat shows the path of an abstract socket prefixed with '@', however
the <path> argument should not have this leading character.
