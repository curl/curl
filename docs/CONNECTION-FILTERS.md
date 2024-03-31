<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl connection filters

Connection filters is a design in the internals of curl, not visible in its
public API. They were added in curl v7.87.0. This document describes the
concepts, its high level implementation and the motivations.

## Filters

A "connection filter" is a piece of code that is responsible for handling a
range of operations of curl's connections: reading, writing, waiting on
external events, connecting and closing down - to name the most important
ones.

The most important feat of connection filters is that they can be stacked on
top of each other (or "chained" if you prefer that metaphor). In the common
scenario that you want to retrieve a `https:` URL with curl, you need 2 basic
things to send the request and get the response: a TCP connection, represented
by a `socket` and a SSL instance en- and decrypt over that socket. You write
your request to the SSL instance, which encrypts and writes that data to the
socket, which then sends the bytes over the network.

With connection filters, curl's internal setup looks something like this (cf
for connection filter):

```
Curl_easy *data         connectdata *conn        cf-ssl        cf-socket
+----------------+      +-----------------+      +-------+     +--------+
|https://curl.se/|----> | properties      |----> | keys  |---> | socket |--> OS --> network
+----------------+      +-----------------+      +-------+     +--------+

 Curl_write(data, buffer)
  --> Curl_cfilter_write(data, data->conn, buffer)
       ---> conn->filter->write(conn->filter, data, buffer)
```

While connection filters all do different things, they look the same from the
"outside". The code in `data` and `conn` does not really know **which**
filters are installed. `conn` just writes into the first filter, whatever that
is.

Same is true for filters. Each filter has a pointer to the `next` filter. When
SSL has encrypted the data, it does not write to a socket, it writes to the
next filter. If that is indeed a socket, or a file, or an HTTP/2 connection is
of no concern to the SSL filter.

This allows stacking, as in:

```
Direct:
  http://localhost/      conn -> cf-socket
  https://curl.se/       conn -> cf-ssl -> cf-socket
Via http proxy tunnel:
  http://localhost/      conn -> cf-http-proxy -> cf-socket
  https://curl.se/       conn -> cf-ssl -> cf-http-proxy -> cf-socket
Via https proxy tunnel:
  http://localhost/      conn -> cf-http-proxy -> cf-ssl -> cf-socket
  https://curl.se/       conn -> cf-ssl -> cf-http-proxy -> cf-ssl -> cf-socket
Via http proxy tunnel via SOCKS proxy:
  http://localhost/      conn -> cf-http-proxy -> cf-socks -> cf-socket
```

### Connecting/Closing

Before `Curl_easy` can send the request, the connection needs to be
established. This means that all connection filters have done, whatever they
need to do: waiting for the socket to be connected, doing the TLS handshake,
performing the HTTP tunnel request, etc. This has to be done in reverse order:
the last filter has to do its connect first, then the one above can start,
etc.

Each filter does in principle the following:

```
static CURLcode
myfilter_cf_connect(struct Curl_cfilter *cf,
                    struct Curl_easy *data,
                    bool *done)
{
  CURLcode result;

  if(cf->connected) {            /* we and all below are done */
    *done = TRUE;
    return CURLE_OK;
  }
                                 /* Let the filters below connect */
  result = cf->next->cft->connect(cf->next, data, blocking, done);
  if(result || !*done)
    return result;               /* below errored/not finished yet */

  /* MYFILTER CONNECT THINGS */  /* below connected, do out thing */
  *done = cf->connected = TRUE;  /* done, remember, return */
  return CURLE_OK;
}
```

Closing a connection then works similar. The `conn` tells the first filter to
close. Contrary to connecting, the filter does its own things first, before
telling the next filter to close.

### Efficiency

There are two things curl is concerned about: efficient memory use and fast
transfers.

The memory footprint of a filter is relatively small:

```
struct Curl_cfilter {
  const struct Curl_cftype *cft; /* the type providing implementation */
  struct Curl_cfilter *next;     /* next filter in chain */
  void *ctx;                     /* filter type specific settings */
  struct connectdata *conn;      /* the connection this filter belongs to */
  int sockindex;                 /* TODO: like to get rid off this */
  BIT(connected);                /* != 0 iff this filter is connected */
};
```

The filter type `cft` is a singleton, one static struct for each type of
filter. The `ctx` is where a filter holds its specific data. That varies by
filter type. An http-proxy filter keeps the ongoing state of the CONNECT here,
free it after its has been established. The SSL filter keeps the `SSL*` (if
OpenSSL is used) here until the connection is closed. So, this varies.

`conn` is a reference to the connection this filter belongs to, so nothing
extra besides the pointer itself.

Several things, that before were kept in `struct connectdata`, now goes into
the `filter->ctx` *when needed*. So, the memory footprint for connections that
do *not* use an http proxy, or socks, or https is lower.

As to transfer efficiency, writing and reading through a filter comes at near
zero cost *if the filter does not transform the data*. An http proxy or socks
filter, once it is connected, just passes the calls through. Those filters
implementations look like this:

```
ssize_t  Curl_cf_def_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err)
{
  return cf->next->cft->do_send(cf->next, data, buf, len, err);
}
```
The `recv` implementation is equivalent.

## Filter Types

The currently existing filter types (curl 8.5.0) are:

* `TCP`, `UDP`, `UNIX`: filters that operate on a socket, providing raw I/O.
* `SOCKET-ACCEPT`: special TCP socket that has a socket that has been
  `accept()`ed in a `listen()`
* `SSL`: filter that applies TLS en-/decryption and handshake. Manages the
  underlying TLS backend implementation.
* `HTTP-PROXY`, `H1-PROXY`, `H2-PROXY`: the first manages the connection to an
  HTTP proxy server and uses the other depending on which ALPN protocol has
  been negotiated.
* `SOCKS-PROXY`: filter for the various SOCKS proxy protocol variations
* `HAPROXY`: filter for the protocol of the same name, providing client IP
  information to a server.
* `HTTP/2`: filter for handling multiplexed transfers over an HTTP/2
  connection
* `HTTP/3`: filter for handling multiplexed transfers over an HTTP/3+QUIC
  connection
* `HAPPY-EYEBALLS`: meta filter that implements IPv4/IPv6 "happy eyeballing".
  It creates up to 2 sub-filters that race each other for a connection.
* `SETUP`: meta filter that manages the creation of sub-filter chains for a
  specific transport (e.g. TCP or QUIC).
* `HTTPS-CONNECT`: meta filter that races a TCP+TLS and a QUIC connection
  against each other to determine if HTTP/1.1, HTTP/2 or HTTP/3 shall be used
  for a transfer.

Meta filters are combining other filters for a specific purpose, mostly during
connection establishment. Other filters like `TCP`, `UDP` and `UNIX` are only
to be found at the end of filter chains. SSL filters provide encryption, of
course. Protocol filters change the bytes sent and received.

## Filter Flags

Filter types carry flags that inform what they do. These are (for now):

* `CF_TYPE_IP_CONNECT`: this filter type talks directly to a server. This does
  not have to be the server the transfer wants to talk to. For example when a
  proxy server is used.
* `CF_TYPE_SSL`: this filter type provides encryption.
* `CF_TYPE_MULTIPLEX`: this filter type can manage multiple transfers in parallel.

Filter types can combine these flags. For example, the HTTP/3 filter types
have `CF_TYPE_IP_CONNECT`, `CF_TYPE_SSL` and `CF_TYPE_MULTIPLEX` set.

Flags are useful to extrapolate properties of a connection. To check if a
connection is encrypted, libcurl inspect the filter chain in place, top down,
for `CF_TYPE_SSL`. If it finds `CF_TYPE_IP_CONNECT` before any `CF_TYPE_SSL`,
the connection is not encrypted.

For example, `conn1` is for a `http:` request using a tunnel through an HTTP/2
`https:` proxy. `conn2` is a `https:` HTTP/2 connection to the same proxy.
`conn3` uses HTTP/3 without proxy. The filter chains would look like this
(simplified):

```
conn1 --> `HTTP-PROXY` --> `H2-PROXY` --> `SSL` --> `TCP`
flags:                     `IP_CONNECT`   `SSL`     `IP_CONNECT`

conn2 --> `HTTP/2` --> `SSL` --> `HTTP-PROXY` --> `H2-PROXY` --> `SSL` --> `TCP`
flags:                 `SSL`                      `IP_CONNECT`   `SSL`     `IP_CONNECT`

conn3 --> `HTTP/3`
flags:    `SSL|IP_CONNECT`
```

Inspecting the filter chains, `conn1` is seen as unencrypted, since it
contains an `IP_CONNECT` filter before any `SSL`. `conn2` is clearly encrypted
as an `SSL` flagged filter is seen first. `conn3` is also encrypted as the
`SSL` flag is checked before the presence of `IP_CONNECT`.

Similar checks can determine if a connection is multiplexed or not.

## Filter Tracing

Filters may make use of special trace macros like `CURL_TRC_CF(data, cf, msg,
...)`. With `data` being the transfer and `cf` being the filter instance.
These traces are normally not active and their execution is guarded so that
they are cheap to ignore.

Users of `curl` may activate them by adding the name of the filter type to the
`--trace-config` argument. For example, in order to get more detailed tracing
of an HTTP/2 request, invoke curl with:

```
> curl -v --trace-config ids,time,http/2  https://curl.se
```

Which gives you trace output with time information, transfer+connection ids
and details from the `HTTP/2` filter. Filter type names in the trace config
are case insensitive. You may use `all` to enable tracing for all filter
types. When using `libcurl` you may call `curl_global_trace(config_string)` at
the start of your application to enable filter details.

## Meta Filters

Meta filters is a catch-all name for filter types that do not change the
transfer data in any way but provide other important services to curl. In
general, it is possible to do all sorts of silly things with them. One of the
commonly used, important things is "eyeballing".

The `HAPPY-EYEBALLS` filter is involved in the connect phase. Its job is to
try the various IPv4 and IPv6 addresses that are known for a server. If only
one address family is known (or configured), it tries the addresses one after
the other with timeouts calculated from the amount of addresses and the
overall connect timeout.

When more than one address family is to be tried, it splits the address list
into IPv4 and IPv6 and makes parallel attempts. The connection filter chain
looks like this:

```
* create connection for http://curl.se
conn[curl.se] --> SETUP[TCP] --> HAPPY-EYEBALLS --> NULL
* start connect
conn[curl.se] --> SETUP[TCP] --> HAPPY-EYEBALLS --> NULL
                                 - ballerv4 --> TCP[151.101.1.91]:443
                                 - ballerv6 --> TCP[2a04:4e42:c00::347]:443
* v6 answers, connected
conn[curl.se] --> SETUP[TCP] --> HAPPY-EYEBALLS --> TCP[2a04:4e42:c00::347]:443
* transfer
```

The modular design of connection filters and that we can plug them into each other is used to control the parallel attempts. When a `TCP` filter does not connect (in time), it is torn down and another one is created for the next address. This keeps the `TCP` filter simple. 

The `HAPPY-EYEBALLS` on the other hand stays focused on its side of the problem. We can use it also to make other type of connection by just giving it another filter type to try to have happy eyeballing for QUIC:

```
* create connection for --http3-only https://curl.se
conn[curl.se] --> SETUP[QUIC] --> HAPPY-EYEBALLS --> NULL
* start connect
conn[curl.se] --> SETUP[QUIC] --> HAPPY-EYEBALLS --> NULL
                                  - ballerv4 --> HTTP/3[151.101.1.91]:443
                                  - ballerv6 --> HTTP/3[2a04:4e42:c00::347]:443
* v6 answers, connected
conn[curl.se] --> SETUP[QUIC] --> HAPPY-EYEBALLS --> HTTP/3[2a04:4e42:c00::347]:443
* transfer
```

When we plug these two variants together, we get the `HTTPS-CONNECT` filter
type that is used for `--http3` when **both** HTTP/3 and HTTP/2 or HTTP/1.1
shall be attempted:

```
* create connection for --http3 https://curl.se
conn[curl.se] --> HTTPS-CONNECT --> NULL
* start connect
conn[curl.se] --> HTTPS-CONNECT --> NULL
                  - SETUP[QUIC] --> HAPPY-EYEBALLS --> NULL
                                    - ballerv4 --> HTTP/3[151.101.1.91]:443
                                    - ballerv6 --> HTTP/3[2a04:4e42:c00::347]:443
                  - SETUP[TCP]  --> HAPPY-EYEBALLS --> NULL
                                    - ballerv4 --> TCP[151.101.1.91]:443
                                    - ballerv6 --> TCP[2a04:4e42:c00::347]:443
* v4 QUIC answers, connected
conn[curl.se] --> HTTPS-CONNECT --> SETUP[QUIC] --> HAPPY-EYEBALLS --> HTTP/3[151.101.1.91]:443
* transfer
```
