Long: abstract-unix-socket
Arg: <path>
Help: Connect via abstract Unix domain socket
Added: 7.53.0
Protocols: HTTP
---
Connect through an abstract Unix domain socket, instead of using the network.
Note: netstat shows the path of an abstract socket prefixed with '@', however
the <path> argument should not have this leading character.
