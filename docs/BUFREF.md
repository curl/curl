# bufref

This is an internal module for handling buffer references. A referenced
buffer is associated with its destructor function that is implicitly called
when the reference is invalidated. Once referenced, a buffer cannot be
reallocated.

A data length is stored within the reference for binary data handling
purposes; it is not used by the bufref API.

The `struct bufref` is used to hold data referencing a buffer. The members of
that structure **MUST NOT** be accessed or modified without using the dedicated
bufref API.

## init

```c
void Curl_bufref_init(struct bufref *br);
```

Initialises a `bufref` structure. This function **MUST** be called before any
other operation is performed on the structure.

Upon completion, the referenced buffer is `NULL` and length is zero.

This function may also be called to bypass referenced buffer destruction while
invalidating the current reference.

## free

```c
void Curl_bufref_free(struct bufref *br);
```

Destroys the previously referenced buffer using its destructor and
reinitialises the structure for a possible subsequent reuse.

## set

```c
void Curl_bufref_set(struct bufref *br, const void *buffer, size_t length,
                     void (*destructor)(void *));
```

Releases the previously referenced buffer, then assigns the new `buffer` to
the structure, associated with its `destructor` function. The latter can be
specified as `NULL`: this will be the case when the referenced buffer is
static.

if `buffer` is NULL, `length`must be zero.

## memdup

```c
CURLcode Curl_bufref_memdup(struct bufref *br, const void *data, size_t length);
```

Releases the previously referenced buffer, then duplicates the `length`-byte
`data` into a buffer allocated via `malloc()` and references the latter
associated with destructor `curl_free()`.

An additional trailing byte is allocated and set to zero as a possible
string zero-terminator; it is not counted in the stored length.

Returns `CURLE_OK` if successful, else `CURLE_OUT_OF_MEMORY`.

## ptr

```c
const unsigned char *Curl_bufref_ptr(const struct bufref *br);
```

Returns a `const unsigned char *` to the referenced buffer.

## len

```c
size_t Curl_bufref_len(const struct bufref *br);
```

Returns the stored length of the referenced buffer.
