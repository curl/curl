---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: connect-to
Arg: <HOST1:PORT1:HOST2:PORT2>
Help: Connect to host2 instead of host1
Added: 7.49.0
Category: connection dns
Multi: append
See-also:
  - resolve
  - header
Example:
  - --connect-to example.com:443:example.net:8443 $URL
---

# `--connect-to`

For a request intended for the `HOST1:PORT1` pair, connect to `HOST2:PORT2`
instead. This option is only used to establish the network connection. It does
NOT affect the hostname/port number that is used for TLS/SSL (e.g. SNI,
certificate verification) or for the application protocols.

`HOST1` and `PORT1` may be empty strings, meaning any host or any port number.
`HOST2` and `PORT2` may also be empty strings, meaning use the request's
original hostname and port number.

A hostname specified to this option is compared as a string, so it needs to
match the name used in request URL. It can be either numerical such as
`127.0.0.1` or the full host name such as `example.org`.

Example: redirect connects from the example.com hostname to 127.0.0.1
independently of port number:

    curl --connect-to example.com::127.0.0.1: https://example.com/

Example: redirect connects from all hostnames to 127.0.0.1 independently of
port number:

    curl --connect-to ::127.0.0.1: http://example.com/
