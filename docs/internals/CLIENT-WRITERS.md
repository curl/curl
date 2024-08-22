<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# curl client writers

Client writers is a design in the internals of libcurl, not visible in its public API. They were started
in curl v8.5.0. This document describes the concepts, its high level implementation and the motivations.

## Naming

`libcurl` operates between clients and servers. A *client* is the application using libcurl, like the command line tool `curl` itself. Data to be uploaded to a server is **read** from the client and **send** to the server, the servers response is **received** by `libcurl` and then **written** to the client.

With this naming established, client writers are concerned with writing responses from the server to the application. Applications register callbacks via `CURLOPT_WRITEFUNCTION` and `CURLOPT_HEADERFUNCTION` to be invoked by `libcurl` when the response is received.

## Invoking

All code in `libcurl` that handles response data is ultimately expected to forward this data via `Curl_client_write()` to the application. The exact prototype of this function is:

```
CURLcode Curl_client_write(struct Curl_easy *data, int type, const char *buf, size_t blen);
```
The `type` argument specifies what the bytes in `buf` actually are. The following bits are defined:

```
#define CLIENTWRITE_BODY    (1<<0) /* non-meta information, BODY */
#define CLIENTWRITE_INFO    (1<<1) /* meta information, not a HEADER */
#define CLIENTWRITE_HEADER  (1<<2) /* meta information, HEADER */
#define CLIENTWRITE_STATUS  (1<<3) /* a special status HEADER */
#define CLIENTWRITE_CONNECT (1<<4) /* a CONNECT related HEADER */
#define CLIENTWRITE_1XX     (1<<5) /* a 1xx response related HEADER */
#define CLIENTWRITE_TRAILER (1<<6) /* a trailer HEADER */
```

The main types here are `CLIENTWRITE_BODY` and `CLIENTWRITE_HEADER`. They are
mutually exclusive. The other bits are enhancements to `CLIENTWRITE_HEADER` to
specify what the header is about. They are only used in HTTP and related
protocols (RTSP and WebSocket).

The implementation of `Curl_client_write()` uses a chain of *client writer* instances to process the call and make sure that the bytes reach the proper application callbacks. This is similar to the design of connection filters: client writers can be chained to process the bytes written through them. The definition is:

```
struct Curl_cwtype {
  const char *name;
  CURLcode (*do_init)(struct Curl_easy *data,
                      struct Curl_cwriter *writer);
  CURLcode (*do_write)(struct Curl_easy *data,
                       struct Curl_cwriter *writer, int type,
                       const char *buf, size_t nbytes);
  void (*do_close)(struct Curl_easy *data,
                   struct Curl_cwriter *writer);
};

struct Curl_cwriter {
  const struct Curl_cwtype *cwt;  /* type implementation */
  struct Curl_cwriter *next;  /* Downstream writer. */
  Curl_cwriter_phase phase; /* phase at which it operates */
};
```

`Curl_cwriter` is a writer instance with a `next` pointer to form the chain. It has a type `cwt` which provides the implementation. The main callback is `do_write()` that processes the data and calls then the `next` writer. The others are for setup and tear down.

## Phases and Ordering

Since client writers may transform the bytes written through them, the order in which the are called is relevant for the outcome. When a writer is created, one property it gets is the `phase` in which it operates. Writer phases are defined like:

```
typedef enum {
  CURL_CW_RAW,  /* raw data written, before any decoding */
  CURL_CW_TRANSFER_DECODE, /* remove transfer-encodings */
  CURL_CW_PROTOCOL, /* after transfer, but before content decoding */
  CURL_CW_CONTENT_DECODE, /* remove content-encodings */
  CURL_CW_CLIENT  /* data written to client */
} Curl_cwriter_phase;
```

If a writer for phase `PROTOCOL` is added to the chain, it is always added *after* any `RAW` or `TRANSFER_DECODE` and *before* any `CONTENT_DECODE` and `CLIENT` phase writer. If there is already a writer for the same phase present, the new writer is inserted just before that one.

All transfers have a chain of 3 writers by default. A specific protocol handler may alter that by adding additional writers. The 3 standard writers are (name, phase):

1. `"raw", CURL_CW_RAW `: if the transfer is verbose, it forwards the body data to the debug function.
1. `"download", CURL_CW_PROTOCOL`: checks that protocol limits are kept and updates progress counters. When a download has a known length, it checks that it is not exceeded and errors otherwise.
1. `"client", CURL_CW_CLIENT`: the main work horse. It invokes the application callbacks or writes to the configured file handles. It chops large writes into smaller parts, as documented for `CURLOPT_WRITEFUNCTION`. If also handles *pausing* of transfers when the application callback returns `CURL_WRITEFUNC_PAUSE`.

With these writers always in place, libcurl's protocol handlers automatically have these implemented.

## Enhanced Use

HTTP is the protocol in curl that makes use of the client writer chain by
adding writers to it. When the `libcurl` application set
`CURLOPT_ACCEPT_ENCODING` (as `curl` does with `--compressed`), the server is
offered an `Accept-Encoding` header with the algorithms supported. The server
then may choose to send the response body compressed. For example using `gzip`
or `brotli` or even both.

In the server's response, if there is a `Content-Encoding` header listing the
encoding applied. If supported by `libcurl` it then decompresses the content
before writing it out to the client. How does it do that?

The HTTP protocol adds client writers in phase `CURL_CW_CONTENT_DECODE` on
seeing such a header. For each encoding listed, it adds the corresponding
writer. The response from the server is then passed through
`Curl_client_write()` to the writers that decode it. If several encodings had
been applied the writer chain decodes them in the proper order.

When the server provides a `Content-Length` header, that value applies to the
*compressed* content. Length checks on the response bytes must happen *before*
it gets decoded. That is why this check happens in phase `CURL_CW_PROTOCOL`
which always is ordered before writers in phase `CURL_CW_CONTENT_DECODE`.

What else?

Well, HTTP servers may also apply a `Transfer-Encoding` to the body of a response. The most well-known one is `chunked`, but algorithms like `gzip` and friends could also be applied. The difference to content encodings is that decoding needs to happen *before* protocol checks, for example on length, are done.

That is why transfer decoding writers are added for phase `CURL_CW_TRANSFER_DECODE`. Which makes their operation happen *before* phase `CURL_CW_PROTOCOL` where length may be checked.

## Summary

By adding the common behavior of all protocols into `Curl_client_write()` we make sure that they do apply everywhere. Protocol handler have less to worry about. Changes to default behavior can be done without affecting handler implementations.

Having a writer chain as implementation allows protocol handlers with extra needs, like HTTP, to add to this for special behavior. The common way of writing the actual response data stays the same.
