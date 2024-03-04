# curl client readers

Client readers is a design in the internals of libcurl, not visible in its public API. They were started
in curl v8.7.0. This document describes the concepts, its high level implementation and the motivations.

## Naming

`libcurl` operates between clients and servers. A *client* is the application using libcurl, like the command line tool `curl` itself. Data to be uploaded to a server is **read** from the client and **sent** to the server, the servers response is **received** by `libcurl` and then **written** to the client.

With this naming established, client readers are concerned with providing data from the application to the server. Applications register callbacks via `CURLOPT_READFUNCTION`, data via `CURLOPT_POSTFIELDS` and other options to be used by `libcurl` when the request is send.

## Invoking

The transfer loop that sends and receives, is using `Curl_client_read()` to get more data to send for a transfer. If no specific reader has been installed yet, the default one that uses `CURLOPT_READFUNCTION` is added. The prototype is

```
CURLcode Curl_client_read(struct Curl_easy *data, char *buf, size_t blen,
                          size_t *nread, bool *eos);
```
The arguments are the transfer to read for, a buffer to hold the read data, its length, the actual number of bytes placed into the buffer and the `eos` (*end of stream*) flag indicating that no more data is available. The `eos` flag may be set for a read amount, if that amount was the last. That way curl can avoid to read an additional time.

The implementation of `Curl_client_read()` uses a chain of *client reader* instances to get the data. This is similar to the design of *client writers*. The chain of readers allows processing of the data to send.

The definition of a reader is:

```
struct Curl_crtype {
  const char *name;        /* writer name. */
  CURLcode (*do_init)(struct Curl_easy *data, struct Curl_creader *writer);
  CURLcode (*do_read)(struct Curl_easy *data, struct Curl_creader *reader,
                      char *buf, size_t blen, size_t *nread, bool *eos);
  void (*do_close)(struct Curl_easy *data, struct Curl_creader *reader);
  bool (*needs_rewind)(struct Curl_easy *data, struct Curl_creader *reader);
};

struct Curl_creader {
  const struct Curl_crtype *crt;  /* type implementation */
  struct Curl_creader *next;  /* Downstream reader. */
  Curl_creader_phase phase; /* phase at which it operates */
};
```

`Curl_creader` is a reader instance with a `next` pointer to form the chain. It as a type `crt` which provides the implementation. The main callback is `do_read()` which provides the data to the caller. The others are for setup and tear down. `needs_rewind()` is explained further below.

## Phases and Ordering

Since client readers may transform the data being read through the chain, the order in which they are called is relevant for the outcome. When a reader is created, it gets the `phase` property in which it operates. Reader phases are defined like:

```
typedef enum {
  CURL_CR_NET,  /* data send to the network (connection filters) */
  CURL_CR_TRANSFER_ENCODE, /* add transfer-encodings */
  CURL_CR_PROTOCOL, /* before transfer, but after content decoding */
  CURL_CR_CONTENT_ENCODE, /* add content-encodings */
  CURL_CR_CLIENT  /* data read from client */
} Curl_creader_phase;
```

If a reader for phase `PROTOCOL` is added to the chain, it is always added *after* any `NET` or `TRANSFER_ENCODE` readers and *before* and `CONTENT_ENCODE` and `CLIENT` readers. If there is already a reader for the same phase, the new reader is added before the existing one(s).

### Example: `chunked` reader

In `http_chunks.c` a client reader for chunked uploads is implemented. This one operates at phase `CURL_CR_TRANSFER_ENCODE`. Any data coming from the reader "below" has the HTTP/1.1 chunk handling applied and returned to the caller.

When this reader sees an `eos` from below, it generates the terminal chunk, adding trailers if provided by the application. When that last chunk is fully returned, it also sets `eos` to the caller.

### Example: `lineconv` reader

In `sendf.c` a client reader that does line-end conversions is implemented. It operates at `CURL_CR_CONTENT_ENCODE` and converts any "\n" to "\r\n". This is used for FTP ASCII uploads or when the general `crlf` options has been set.

### Example: `null` reader

Implemented in `sendf.c` for phase `CURL_CR_CLIENT`, this reader has the simple job of providing transfer bytes of length 0 to the caller, immediately indicating an `eos`. This reader is installed by HTTP for all GET/HEAD requests and when authentication is being negotiated.

### Example: `buf` reader

Implemented in `sendf.c` for phase `CURL_CR_CLIENT`, this reader get a buffer pointer and a length and provides exactly these bytes. This one is used in HTTP for sending `postfields` provided by the application.

## Request retries

Sometimes it is necessary to send a request with client data again. Transfer handling can inquire via `Curl_client_read_needs_rewind()` if a rewind (e.g. a reset of the client data) is necessary. This asks all installed readers if they need it and give `FALSE` of none does.

## Summary and Outlook

By adding the client reader interface, any protocol can control how/if it wants the curl transfer to send bytes for a request. The transfer loop becomes then blissfully ignorant of the specifics. 

The protocols on the other hand no longer have to care to package data most efficiently. At any time, should more data be needed, it can be read from the client. This is used when sending HTTP requests headers to add as much request body data to the initial sending as there is room for.

Future enhancements based on the client readers:
* delegate the actual "rewinding" to the readers. The should know how it is done, eliminating the `readrewind.c` protocol specifics in `multi.c`.
* `expect-100` handling: place that into a HTTP specific reader at `CURL_CR_PROTOCOL` and eliminate the checks in the generic transfer parts.
* `eos` detection: `upload_done` is partly triggered now by comparing the number of bytes sent to a known size. This is no longer necessary since the core readers obey length restrictions.
* `eos forwarding`: transfer should forward an `eos` flag to the connection filters. Filters like HTTP/2 and HTTP/3 can make use of that, terminating streams early. This would also eliminate length checks in stream handling.
