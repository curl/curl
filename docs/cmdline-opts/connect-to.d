Long: connect-to
Arg: <HOST1:PORT1:HOST2:PORT2>
Help: Connect to host
Added: 7.49.0
See-also: resolve header
---

For a request to the given HOST:PORT pair, connect to
CONNECT-TO-HOST:CONNECT-TO-PORT instead.  This option is suitable to direct
requests at a specific server, e.g. at a specific cluster node in a cluster of
servers.  This option is only used to establish the network connection. It
does NOT affect the hostname/port that is used for TLS/SSL (e.g. SNI,
certificate verification) or for the application protocols.  "host" and "port"
may be the empty string, meaning "any host/port".  "connect-to-host" and
"connect-to-port" may also be the empty string, meaning "use the request's
original host/port".

This option can be used many times to add many connect rules.
