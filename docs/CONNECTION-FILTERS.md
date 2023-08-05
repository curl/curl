# curl connection filters

Connection filters is a design in the internals of curl, not visible in its public API. They were added 
in curl v7.xx.x. This document describes the concepts, its high level implementation and the motivations.

## Filters

A "connection filter" is a piece of code that is responsible for handling a range of operations
of curl's connections: reading, writing, waiting on external events, connecting and closing down - to name the most important ones.

The most important feat of connection filters is that they can be stacked on top of each other (or "chained" if you prefer that metaphor). In the common scenario that you want to retrieve a `https:` url with curl, you need 2 basic things to send the request and get the response: a TCP connection, represented by a `socket` and a SSL instance en- and decrypt over that socket. You write your request to the SSL instance, which encrypts and writes that data to the socket, which then sends the bytes over the network.

With connection filters, curl's internal setup will look something like this (cf for connection filter):

```
Curl_easy *data         connectdata *conn        cf-ssl        cf-socket
+----------------+      +-----------------+      +-------+     +--------+
|https://curl.se/|----> | properties      |----> | keys  |---> | socket |--> OS --> network
+----------------+      +-----------------+      +-------+     +--------+

 Curl_write(data, buffer)
  --> Curl_cfilter_write(data, data->conn, buffer)
       ---> conn->filter->write(conn->filter, data, buffer)
```

While connection filters all do different things, they look the same from the "outside". The code in `data` and `conn` does not really know **which** filters are installed. `conn` just writes into the first filter, whatever that is.

Same is true for filters. Each filter has a pointer to the `next` filter. When SSL has encrypted the data, it does not write to a socket, it writes to the next filter. If that is indeed a socket, or a file, or an HTTP/2 connection is of no concern to the SSL filter.

And this allows the stacking, as in:

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

Before `Curl_easy` can send the request, the connection needs to be established. This means that all connection filters have done, whatever they need to do: waiting for the socket to be connected, doing the TLS handshake, performing the HTTP tunnel request, etc. This has to be done in reverse order: the last filter has to do its connect first, then the one above can start, etc.

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

Closing a connection then works similar. The `conn` tells the first filter to close. Contrary to connecting,
the filter does its own things first, before telling the next filter to close.

### Efficiency

There are two things curl is concerned about: efficient memory use and fast transfers.

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
The filter type `cft` is a singleton, one static struct for each type of filter. The `ctx` is where a filter will hold its specific data. That varies by filter type. An http-proxy filter will keep the ongoing state of the CONNECT here, but free it after its has been established. The SSL filter will keep the `SSL*` (if OpenSSL is used) here until the connection is closed. So, this varies.

`conn` is a reference to the connection this filter belongs to, so nothing extra besides the pointer itself.

Several things, that before were kept in `struct connectdata`, will now go into the `filter->ctx` *when needed*. So, the memory footprint for connections that do *not* use an http proxy, or socks, or https will be lower.

As to transfer efficiency, writing and reading through a filter comes at near zero cost *if the filter does not transform the data*. An http proxy or socks filter, once it is connected, will just pass the calls through. Those filters implementations will look like this:

```
ssize_t  Curl_cf_def_send(struct Curl_cfilter *cf, struct Curl_easy *data,
                          const void *buf, size_t len, CURLcode *err)
{
  return cf->next->cft->do_send(cf->next, data, buf, len, err);
}
```
The `recv` implementation is equivalent.

## Filter Types

The (currently) existing filter types are: SOCKET, SOCKET-ACCEPT, SSL, HTTP-PROXY and SOCKS-PROXY. Vital to establishing and read/writing a connection. But filters are also a good way to implement tasks for *managing* a connection:

* **Statistics**: a filter that counts the number of bytes sent/received. Place one in front of SOCKET and one higher up and get the number of raw and "easy" bytes transferred. They may track the speed as well, or number of partial writes, etc.
* **Timeout**: enforce timeouts, e.g. fail if a connection cannot be established in a certain amount of time.
* **Progress**: report progress on a connection.
* **Pacing**: limit read/write rates.
* **Testing**: simulate network condition or failures.

As you see, filters are a good way to add functionality to curl's internal handling of transfers without impact on other code.

## Easy Filters?

Some things that curl needs to manage are not directly tied to a specific connection but the property of the `Curl_easy` handle, e.g. a particular transfer. When using HTTP/2 or HTTP/3, many transfers can use the same connection. If one wants to monitor of the transfer itself or restricting its speed alone, a connection filter is not the right place to do this.

So we might add "easy filters" one day. Who knows?
