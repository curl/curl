# dynbuf

This is the internal module for creating and handling "dynamic buffers". This
means buffers that can be appended to, dynamically and grow to adapt.

There will always be a terminating zero put at the end of the dynamic buffer.

The `struct dynbuf` is used to hold data for each instance of a dynamic
buffer. The members of that struct **MUST NOT** be accessed or modified
without using the dedicated dynbuf API.

## `Curl_dyn_init`

```c
void Curl_dyn_init(struct dynbuf *s, size_t toobig);
```

This initializes a struct to use for dynbuf and it cannot fail. The `toobig`
value **must** be set to the maximum size we allow this buffer instance to
grow to. The functions below will return `CURLE_OUT_OF_MEMORY` when hitting
this limit.

## `Curl_dyn_free`

```c
void Curl_dyn_free(struct dynbuf *s);
```

Free the associated memory and clean up. After a free, the `dynbuf` struct can
be re-used to start appending new data to.

## `Curl_dyn_addn`

```c
CURLcode Curl_dyn_addn(struct dynbuf *s, const void *mem, size_t len);
```

Append arbitrary data of a given length to the end of the buffer.

If this function fails it calls `Curl_dyn_free` on `dynbuf`.

## `Curl_dyn_add`

```c
CURLcode Curl_dyn_add(struct dynbuf *s, const char *str);
```

Append a C string to the end of the buffer.

If this function fails it calls `Curl_dyn_free` on `dynbuf`.

## `Curl_dyn_addf`

```c
CURLcode Curl_dyn_addf(struct dynbuf *s, const char *fmt, ...);
```

Append a `printf()`-style string to the end of the buffer.

If this function fails it calls `Curl_dyn_free` on `dynbuf`.

## `Curl_dyn_vaddf`

```c
CURLcode Curl_dyn_vaddf(struct dynbuf *s, const char *fmt, va_list ap);
```

Append a `vprintf()`-style string to the end of the buffer.

If this function fails it calls `Curl_dyn_free` on `dynbuf`.

## `Curl_dyn_reset`

```c
void Curl_dyn_reset(struct dynbuf *s);
```

Reset the buffer length, but leave the allocation.

## `Curl_dyn_tail`

```c
CURLcode Curl_dyn_tail(struct dynbuf *s, size_t length);
```

Keep `length` bytes of the buffer tail (the last `length` bytes of the
buffer). The rest of the buffer is dropped. The specified `length` must not be
larger than the buffer length. To instead keep the leading part, see
`Curl_dyn_setlen()`.

## `Curl_dyn_ptr`

```c
char *Curl_dyn_ptr(const struct dynbuf *s);
```

Returns a `char *` to the buffer if it has a length, otherwise may return
NULL. Since the buffer may be reallocated, this pointer should not be trusted
or used anymore after the next buffer manipulation call.

## `Curl_dyn_uptr`

```c
unsigned char *Curl_dyn_uptr(const struct dynbuf *s);
```

Returns an `unsigned char *` to the buffer if it has a length, otherwise may
return NULL. Since the buffer may be reallocated, this pointer should not be
trusted or used anymore after the next buffer manipulation call.

## `Curl_dyn_len`

```c
size_t Curl_dyn_len(const struct dynbuf *s);
```

Returns the length of the buffer in bytes. Does not include the terminating
zero byte.

## `Curl_dyn_setlen`

```c
CURLcode Curl_dyn_setlen(struct dynbuf *s, size_t len);
```

Sets the new shorter length of the buffer in number of bytes. Keeps the
leftmost set number of bytes, discards the rest. To instead keep the tail part
of the buffer, see `Curl_dyn_tail()`.
