<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# bufq

This is an internal module for managing I/O buffers. A `bufq` can be written
to and read from. It manages read and write positions and has a maximum size.

## read/write

Its basic read/write functions have a similar signature and return code handling
as many internal Curl read and write ones.


```
ssize_t Curl_bufq_write(struct bufq *q, const unsigned char *buf, size_t len, CURLcode *err);

- returns the length written into `q` or -1 on error.
- writing to a full `q` returns -1 and set *err to CURLE_AGAIN

ssize_t Curl_bufq_read(struct bufq *q, unsigned char *buf, size_t len, CURLcode *err);

- returns the length read from `q` or -1 on error.
- reading from an empty `q` returns -1 and set *err to CURLE_AGAIN

```

To pass data into a `bufq` without an extra copy, read callbacks can be used.

```
typedef ssize_t Curl_bufq_reader(void *reader_ctx, unsigned char *buf, size_t len,
                                 CURLcode *err);

ssize_t Curl_bufq_slurp(struct bufq *q, Curl_bufq_reader *reader, void *reader_ctx,
                        CURLcode *err);
```

`Curl_bufq_slurp()` invokes the given `reader` callback, passing it its own
internal buffer memory to write to. It may invoke the `reader` several times,
as long as it has space and while the `reader` always returns the length that
was requested. There are variations of `slurp` that call the `reader` at most
once or only read in a maximum amount of bytes.

The analog mechanism for write out buffer data is:

```
typedef ssize_t Curl_bufq_writer(void *writer_ctx, const unsigned char *buf, size_t len,
                                 CURLcode *err);

ssize_t Curl_bufq_pass(struct bufq *q, Curl_bufq_writer *writer, void *writer_ctx,
                       CURLcode *err);
```

`Curl_bufq_pass()` invokes the `writer`, passing its internal memory and
remove the amount that `writer` reports.

## peek and skip

It is possible to get access to the memory of data stored in a `bufq` with:

```
bool Curl_bufq_peek(const struct bufq *q, const unsigned char **pbuf, size_t *plen);
```

On returning TRUE, `pbuf` points to internal memory with `plen` bytes that one
may read. This is only valid until another operation on `bufq` is performed.

Instead of reading `bufq` data, one may simply skip it:

```
void Curl_bufq_skip(struct bufq *q, size_t amount);
```

This removes `amount` number of bytes from the `bufq`.


## lifetime

`bufq` is initialized and freed similar to the `dynbuf` module. Code using
`bufq` holds a `struct bufq` somewhere. Before it uses it, it invokes:

```
void Curl_bufq_init(struct bufq *q, size_t chunk_size, size_t max_chunks);
```

The `bufq` is told how many "chunks" of data it shall hold at maximum and how
large those "chunks" should be. There are some variants of this, allowing for
more options. How "chunks" are handled in a `bufq` is presented in the section
about memory management.

The user of the `bufq` has the responsibility to call:

```
void Curl_bufq_free(struct bufq *q);
```
to free all resources held by `q`. It is possible to reset a `bufq` to empty via:

```
void Curl_bufq_reset(struct bufq *q);
```

## memory management

Internally, a `bufq` uses allocation of fixed size, e.g. the "chunk_size", up
to a maximum number, e.g. "max_chunks". These chunks are allocated on demand,
therefore writing to a `bufq` may return `CURLE_OUT_OF_MEMORY`. Once the max
number of chunks are used, the `bufq` reports that it is "full".

Each chunks has a `read` and `write` index. A `bufq` keeps its chunks in a
list. Reading happens always at the head chunk, writing always goes to the
tail chunk. When the head chunk becomes empty, it is removed. When the tail
chunk becomes full, another chunk is added to the end of the list, becoming
the new tail.

Chunks that are no longer used are returned to a `spare` list by default. If
the `bufq` is created with option `BUFQ_OPT_NO_SPARES` those chunks are freed
right away.

If a `bufq` is created with a `bufc_pool`, the no longer used chunks are
returned to the pool. Also `bufq` asks the pool for a chunk when it needs one.
More in section "pools".

## empty, full and overflow

One can ask about the state of a `bufq` with methods such as
`Curl_bufq_is_empty(q)`, `Curl_bufq_is_full(q)`, etc. The amount of data held
by a `bufq` is the sum of the data in all its chunks. This is what is reported
by `Curl_bufq_len(q)`.

Note that a `bufq` length and it being "full" are only loosely related. A
simple example:

* create a `bufq` with chunk_size=1000 and max_chunks=4.
* write 4000 bytes to it, it reports "full"
* read 1 bytes from it, it still reports "full"
* read 999 more bytes from it, and it is no longer "full"

The reason for this is that full really means: *bufq uses max_chunks and the
last one cannot be written to*.

When you read 1 byte from the head chunk in the example above, the head still
hold 999 unread bytes. Only when those are also read, can the head chunk be
removed and a new tail be added.

There is another variation to this. If you initialized a `bufq` with option
`BUFQ_OPT_SOFT_LIMIT`, it allows writes **beyond** the `max_chunks`. It
reports **full**, but one can **still** write. This option is necessary, if
partial writes need to be avoided. It means that you need other checks to keep
the `bufq` from growing ever larger and larger.


## pools

A `struct bufc_pool` may be used to create chunks for a `bufq` and keep spare
ones around. It is initialized and used via:

```
void Curl_bufcp_init(struct bufc_pool *pool, size_t chunk_size, size_t spare_max);

void Curl_bufq_initp(struct bufq *q, struct bufc_pool *pool, size_t max_chunks, int opts);
```

The pool gets the size and the mount of spares to keep. The `bufq` gets the
pool and the `max_chunks`. It no longer needs to know the chunk sizes, as
those are managed by the pool.

A pool can be shared between many `bufq`s, as long as all of them operate in
the same thread. In curl that would be true for all transfers using the same
multi handle. The advantages of a pool are:

* when all `bufq`s are empty, only memory for `max_spare` chunks in the pool
  is used. Empty `bufq`s holds no memory.
* the latest spare chunk is the first to be handed out again, no matter which
  `bufq` needs it. This keeps the footprint of "recently used" memory smaller.
