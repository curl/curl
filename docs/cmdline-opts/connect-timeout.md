---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: connect-timeout
Arg: <seconds>
Help: Maximum time allowed to connect
Category: connection timeout
Added: 7.7
Multi: single
See-also:
  - max-time
Example:
  - --connect-timeout 20 $URL
  - --connect-timeout 3.14 $URL
---

# `--connect-timeout`

Maximum time in seconds that you allow curl's connection to take. This only
limits the connection phase, so if curl connects within the given period it
continues - if not it exits.

This option accepts decimal values (added in 7.32.0). The decimal value needs
to be provided using a dot (.) as decimal separator - not the local version
even if it might be using another separator.

The connection phase is usually considered complete when the DNS lookup
and requested TCP, TLS or QUIC handshakes are done.

For several protocols, this includes the authentication, but for HTTP it does
not. HTTP is a request based protocol and authentication happens when the
transfer starts. In FTP however, the authentication is part of the
connect phase, because FTP authorization is part of the connection setup.

WebSocket is a hybrid, using HTTP requests to establish a new connection that
then no longer is HTTP. Since curl 8.24.0, the HTTP request to negotiate a
WebSocket connection is part of the connect phase as well.
