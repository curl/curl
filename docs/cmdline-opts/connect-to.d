c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: connect-to
Arg: <HOST1:PORT1:HOST2:PORT2>
Help: Connect to host
Added: 7.49.0
See-also: resolve header
Category: connection
Example: --connect-to example.com:443:example.net:8443 $URL
---

For a request to the given HOST1:PORT1 pair, connect to HOST2:PORT2 instead.
This option is suitable to direct requests at a specific server, e.g. at a
specific cluster node in a cluster of servers. This option is only used to
establish the network connection. It does NOT affect the hostname/port that is
used for TLS/SSL (e.g. SNI, certificate verification) or for the application
protocols. "HOST1" and "PORT1" may be the empty string, meaning "any
host/port". "HOST2" and "PORT2" may also be the empty string, meaning "use the
request's original host/port".

A "host" specified to this option is compared as a string, so it needs to
match the name used in request URL. It can be either numerical such as
"127.0.0.1" or the full host name such as "example.org".

This option can be used many times to add many connect rules.
