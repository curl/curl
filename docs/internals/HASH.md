<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

# `hash`

    #include "hash.h"

This is the internal module for doing hash tables. A hash table uses a hash
function to compute an index. On each index there is a separate linked list of
entries.

Create a hash table. Add items. Retrieve items. Remove items. Destroy table.

## `Fetch_hash_init`

~~~c
void Fetch_hash_init(struct Fetch_hash *h,
                    size_t slots,
                    hash_function hfunc,
                    comp_function comparator,
                    Fetch_hash_dtor dtor);
~~~

The call initializes a `struct Fetch_hash`.

- `slots` is the number of entries to create in the hash table. Larger is
  better (faster lookups) but also uses more memory.
- `hfunc` is a function pointer to a function that returns a `size_t` value as
  a checksum for an entry in this hash table. Ideally, it returns a unique
  value for every entry ever added to the hash table, but hash collisions are
  handled.
- `comparator` is a function pointer to a function that compares two hash
  table entries. It should return non-zero if the compared items are
  identical.
- `dtor` is a function pointer to a destructor called when an entry is removed
  from the table

## `Fetch_hash_add`

~~~c
void *
Fetch_hash_add(struct Fetch_hash *h, void *key, size_t key_len, void *p)
~~~

This call adds an entry to the hash. `key` points to the hash key and
`key_len` is the length of the hash key. `p` is a custom pointer.

If there already was a match in the hash, that data is replaced with this new
entry.

This function also lazily allocates the table if needed, as it is not done in
the `Fetch_hash_init` function.

Returns NULL on error, otherwise it returns a pointer to `p`.

## `Fetch_hash_add2`

~~~c
void *Fetch_hash_add2(struct Fetch_hash *h, void *key, size_t key_len, void *p,
                     Fetch_hash_elem_dtor dtor)
~~~

This works like `Fetch_hash_add` but has an extra argument: `dtor`, which is a
destructor call for this specific entry. When this entry is removed, this
function is called instead of the function stored for the whole hash table.

## `Fetch_hash_delete`

~~~c
int Fetch_hash_delete(struct Fetch_hash *h, void *key, size_t key_len);
~~~

This function removes an entry from the hash table. If successful, it returns
zero. If the entry was not found, it returns 1.

## `Fetch_hash_pick`

~~~c
void *Fetch_hash_pick(struct Fetch_hash *h, void *key, size_t key_len);
~~~

If there is an entry in the hash that matches the given `key` with size of
`key_len`, that its custom pointer is returned. The pointer that was called
`p` when the entry was added.

It returns NULL if there is no matching entry in the hash.

## `Fetch_hash_destroy`

~~~c
void Fetch_hash_destroy(struct Fetch_hash *h);
~~~

This function destroys a hash and cleanups up all its related data. Calling it
multiple times is fine.

## `Fetch_hash_clean`

~~~c
void Fetch_hash_clean(struct Fetch_hash *h);
~~~

This function removes all the entries in the given hash.

## `Fetch_hash_clean_with_criterium`

~~~c
void
Fetch_hash_clean_with_criterium(struct Fetch_hash *h, void *user,
                               int (*comp)(void *, void *))
~~~

This function removes all the entries in the given hash that matches the
criterion. The provided `comp` function determines if the criteria is met by
returning non-zero.

## `Fetch_hash_count`

~~~c
size_t Fetch_hash_count(struct Fetch_hash *h)
~~~

Returns the number of entries stored in the hash.

## `Fetch_hash_start_iterate`

~~~c
void Fetch_hash_start_iterate(struct Fetch_hash *hash,
                             struct Fetch_hash_iterator *iter):
~~~

This function initializes a `struct Fetch_hash_iterator` that `iter` points to.
It can then be used to iterate over all the entries in the hash.

## `Fetch_hash_next_element`

~~~c
struct Fetch_hash_element *
Fetch_hash_next_element(struct Fetch_hash_iterator *iter);
~~~

Given the iterator `iter`, this function returns a pointer to the next hash
entry if there is one, or NULL if there is no more entries.

Called repeatedly, it iterates over all the entries in the hash table.

Note: it only guarantees functionality if the hash table remains untouched
during its iteration.

# `fetch_off_t` dedicated hash functions

## `Fetch_hash_offt_init`

~~~c
void Fetch_hash_offt_init(struct Fetch_hash *h,
                         size_t slots,
                         Fetch_hash_dtor dtor);
~~~

Initializes a hash table for `fetch_off_t` values. Pass in desired number of
`slots` and `dtor` function.

## `Fetch_hash_offt_set`

~~~c
void *Fetch_hash_offt_set(struct Fetch_hash *h, fetch_off_t id, void *elem);
~~~

Associate a custom `elem` pointer with the given `id`.

## `Fetch_hash_offt_remove`

~~~c
int Fetch_hash_offt_remove(struct Fetch_hash *h, fetch_off_t id);
~~~

Remove the `id` from the hash.

## `Fetch_hash_offt_get`

~~~c
void *Fetch_hash_offt_get(struct Fetch_hash *h, fetch_off_t id);
~~~

Get the pointer associated with the specified `id`.
