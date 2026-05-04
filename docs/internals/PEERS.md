<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl peers

A `peer` in curl internals is represented by a `struct Curl_peer`. It has the following members:

* `scheme`: a `struct Curl_scheme` of the URL schemes known to curl
* `user_hostname`: the hostname as supplied by the user/application
* `hostname`: a *normalized* version of `user_hostname`
* `port`: the network port
* `ipv6`: if `hostname` is an IPv6 address
* `unix_socket`: if `hostname` is a path to a `unix domain socket`
* `user_ipv6zone`: user supplied IPv6 zone name or `NULL`
* `ipv6scope_id`: IPv6 address scope or 0
* `abstract`: (if `unix_socket`) if the socket is abstract

A peer, in short, is a communication endpoint.

## peers and connections

A network connection always goes *somewhere*. That *somewhere* is called
the `origin` of the connection (e.g. the source of responses/downloads).
It is kept in `conn->origin` and is always present in a connection.

The `origin` is *logical* endpoint a connection talks to.

For most connections, the `origin` is connected to *directly*. It
can be directed to another peer, however.

### `connect-to`

With the command line option `--connect-to` or the `libcurl` option
`CURLOPT_CONNECT_TO`, a connection can be told to make the network connection
to another endpoint *while keeping the `origin` unchanged*.

This other endpoint is also a peer and is available as `conn->via_peer`.
This may be a peer for a different hostname and port or it may be a
`unix domain socket`.

### proxies

When a connection uses a proxy, the endpoint for contacting the proxy server
is also represented as a peer and is kept at `conn->socks_proxy.peer` and/or
`conn->http_proxy.peer`. `SOCKS` proxies always come first, so a connection
might connect as:

```
1. curl -------------------------------------------> conn->origin
2. curl -------------------------------------------> conn->via_peer (acting as conn->origin)
3. curl --> socks_proxy.peer ----------------------> conn->via_peer/origin
4. curl -----------------------> http_proxy.peer --> conn->via_peer/origin
5. curl --> socks_proxy.peer --> http_proxy.peer --> conn->via_peer/origin
```

The connection filter `SETUP`, that assembles the filters for a connection,
figures out which peer to pass to which filter in order to make it all work.
The individual filters get passed a specific peer and do not need be concerned
with the whole chain.

For example, IP connection goes to `origin`(1), `via_peer`(2),
`socks_proxy.peer`(3+5), `http_proxy.peer`(4) and that is the peer that gets
passed to the `DNS` and `HAPPY-EYEBALLS` filters.

### TLS

TLS filters' task is to verify the peer they talk to (unless that is
switched off). They either talk to the `conn->origin` or the
`conn->http_proxy.peer` (`SOCKS` does not have TLS). The `conn->via_peer` is
irrelevant. A `via_peer` endpoint needs to present a certificate matching
`conn->origin` or the connect must fail.

### `unix domain socket`s

Peers that represent a `unix domain socket` may be used in two places:

1. `via_peer`: curl can connect to an `origin` server via `unix domain socket`s.
   The disables any proxy settings a transfer might carry.
2. `socks_proxy.peer`: a `SOCKS` proxy may be contacted over a `unix domain
   socket`.

It is not supported to contact an http proxy over `unix domain socket`s.

## peers and credentials

There have been several vulnerabilities by leaking credentials in requests
where they should not appear. In future work we plan to tie credentials to
`peers` and use them only when their `peer` still matches the current
connection use.

## peers internals

A `struct Curl_peer` is allocated with space of the `user_hostname`.
Only when the user supplied value needs conversions (removing `[]` or
IDN encoding) is `hostname` an extra allocation. This keeps the number
of allocations the same as before.

A `Curl_peer` is not expected to be modified after it has been created.
However, each `Curl_peer` has a reference counter. If code want to keep/free
a `peer` the use `Curl_peer_link()/Curl_peer_unlink()`. This modifies the
reference counter, freeing the `peer` once this drops to 0.
This makes is safe and cheap to keep references to peers in connections
and filters.
