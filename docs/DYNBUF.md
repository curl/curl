# dynbuf

This is the internal module for creating and handling "dynamic buffers". This
means buffers that can be appended to, dynamically and grow in size to adapt.

There will always be a terminating zero put at the end of the dynamic buffer.

The `struct dynbuf` is used to hold data for each instance of a dynamic
buffer. The members of that struct **MUST NOT** be accessed or modified
without using the dedicated dynbuf API.

## init

    void Curl_dyn_init(struct dynbuf *s, size_t toobig);

This inits a struct to use for dynbuf and it can't fail. The `toobig` value
**must** be set to the maximum size we allow this buffer instance to grow to.
The functions below will return `CURLE_OUT_OF_MEMORY` when hitting this limit.

## free

    void Curl_dyn_free(struct dynbuf *s);

Free the associated memory and clean up. After a free, the `dynbuf` struct can
be re-used to start appending new data to.

## addn

    CURLcode Curl_dyn_addn(struct dynbuf *s, const void *mem, size_t len);

Append arbitrary data of a given length to the end of the buffer.

## add

    CURLcode Curl_dyn_add(struct dynbuf *s, const char *str);

Append a C string to the end of the buffer.

## addf

    CURLcode Curl_dyn_addf(struct dynbuf *s, const char *fmt, ...);

Append a `printf()`-style string to the end of the buffer.

## reset

    void Curl_dyn_reset(struct dynbuf *s);

Reset the buffer length, but leave the allocation.

## tail

    CURLcode Curl_dyn_trail(struct dynbuf *s, size_t length)

Keep `length` bytes of the buffer tail (the last `length` bytes of the
buffer). The rest of the buffer is dropped. The specified `length` must not be
larger than the buffer length.

## ptr

    char *Curl_dyn_ptr(const struct dynbuf *s);

Returns a `char *` to the buffer if it has a length, otherwise a NULL. Since
the buffer may be reallocated, this pointer should not be trusted or used
anymore after the next buffer manipulation call.

## uptr

    unsigned char *Curl_dyn_uptr(const struct dynbuf *s);

Returns an `unsigned char *` to the buffer if it has a length, otherwise a
NULL. Since the buffer may be reallocated, this pointer should not be trusted
or used anymore after the next buffer manipulation call.

## len

    size_t Curl_dyn_len(const struct dynbuf *s);

Returns the length of the buffer in bytes. Does not include the terminating
zero byte.
