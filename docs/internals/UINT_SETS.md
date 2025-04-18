<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Unsigned Int Sets

The multi handle tracks added easy handles via an unsigned int
it calls an `mid`. There are four data structures for unsigned int
optimized for the multi use case.

## `uint_tbl`

`uint_table`, implemented in `uint-table.[ch]` manages an array
of `void *`. The unsigned int are the index into this array. It is
created with a *capacity* which can be *resized*. The table assigns
the index when a `void *` is *added*. It keeps track of the last
assigned index and uses the next available larger index for a
subsequent add. Reaching *capacity* it wraps around.

The table *can not* store `NULL` values. The largest possible index
is `UINT_MAX - 1`.

The table is iterated over by asking for the *first* existing index,
meaning the smallest number that has an entry, if the table is not
empty. To get the *next* entry, one passes the index of the previous
iteration step. It does not matter if the previous index is still
in the table. Sample code for a table iteration would look like this:

```c
unsigned int mid;
void *entry;

if(Curl_uint_tbl_first(tbl, &mid, &entry)) {
  do {
     /* operate on entry with index mid */
  }
  while(Curl_uint_tbl_next(tbl, mid, &mid, &entry));
}

```

This iteration has the following properties:

* entries in the table can be added/removed safely.
* all entries that are not removed during the iteration are visited.
* the table may be resized to a larger capacity without affecting visited entries.
* entries added with a larger index than the current are visited.

### Memory

For storing 1000 entries, the table would allocate one block of 8KB on a 64-bit system,
plus the 2 pointers and 3 unsigned int in its base `struct uint_tbl`. A resize
allocates a completely new pointer array, copy the existing entries and free the previous one.

### Performance

Lookups of entries are only an index into the array, O(1) with a tiny 1. Adding
entries and iterations are more work:

1. adding an entry means "find the first free index larger than the previous assigned
  one". Worst case for this is a table with only a single free index where `capacity - 1`
  checks on `NULL` values would be performed, O(N). If the single free index is randomly
  distributed, this would be O(N/2).
2. iterating a table scans for the first not `NULL` entry after the start index. This
  makes a complete iteration O(N) work.

In the multi use case, point 1 is remedied by growing the table so that a good chunk
of free entries always exists.

Point 2 is less of an issue for a multi, since it does not really matter when the
number of transfer is relatively small. A multi managing a larger set needs to operate
event based anyway and table iterations rarely are needed.

For these reasons, the simple implementation was preferred. Should this become
a concern, there are options like "free index lists" or, alternatively, an internal
bitset that scans better.

## `uint_bset`

A bitset for unsigned integers, allowing fast add/remove operations. It is initialized
with a *capacity*, meaning it can store only the numbers in the range `[0, capacity-1]`.
It can be *resized* and safely *iterated*. `uint_bset` is designed to operate in combination with `uint_tbl`.

The bitset keeps an array of `curl_uint64_t`. The first array entry keeps the numbers 0 to 63, the
second 64 to 127 and so on. A bitset with capacity 1024 would therefore allocate an array
of 16 64-bit values (128 bytes). Operations for an unsigned int divide it by 64 for the array index and then check/set/clear the bit of the remainder.

Iterator works the same as with `uint_tbl`: ask the bitset for the *first* number present and
then use that to get the *next* higher number present. Like the table, this safe for
adds/removes and growing the set while iterating.

### Memory

The set only needs 1 bit for each possible number.
A bitset for 40000 transfers occupies 5KB of memory.

## Performance

Operations for add/remove/check are O(1). Iteration needs to scan for the next bit set. The
number of scans is small (see memory footprint) and, for checking bits, many compilers
offer primitives for special CPU instructions.

## `uint_spbset`

While the memory footprint of `uint_bset` is good, it still needs 5KB to store the single number 40000. This
is not optimal when many are needed. For example, in event based processing, each socket needs to
keep track of the transfers involved. There are many sockets potentially, but each one mostly tracks
a single transfer or few (on HTTP/2 connection borderline up to 100).

For such uses cases, the `uint_spbset` is intended: track a small number of unsigned int, potentially
rather "close" together. It keeps "chunks" with an offset and has no capacity limit.

Example: adding the number 40000 to an empty sparse bitset would have one chunk with offset 39936, keeping
track of the numbers 39936 to 40192 (a chunk has 4 64-bit values). The numbers in that range can be handled
without further allocations.

The worst case is then storing 100 numbers that lie in separate intervals. Then 100 chunks
would need to be allocated and linked, resulting in overall 4 KB of memory used.

Iterating a sparse bitset works the same as for bitset and table.

## `uint_hash`

At last, there are places in libcurl such as the HTTP/2 and HTTP/3 protocol implementations that need
to store their own data related to a transfer. `uint_hash` allows then to associate an unsigned int,
e.g. the transfer's `mid`, to their own data.
