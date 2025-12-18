<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Multi Identifiers (mid)

All transfers (easy handles) added to a multi handle are assigned
a unique identifier until they are removed again. The multi handle
keeps a table `multi->xfers` that allow O(1) access to the easy
handle by its `mid`.

References to other easy handles *should* keep their `mid`s instead
of a pointer (not all code has been converted as of now). This solves
problems in easy and multi handle life cycle management as well as
iterating over handles where operations may add/remove other handles.

### Values and Lifetime

An `mid` is an `unsigned int`. There are two reserved values:

* `0`: is the `mid` of an internal "admin" handle. Multi and share handles
  each have their own admin handle for maintenance operations, like
  shutting down connections.
* `UINT_MAX`: the "invalid" `mid`. Easy handles are initialized with
  this value. They get it assigned again when removed from
  a multi handle.

This makes potential range of `mid`s from `1` to `UINT_MAX - 1` *inside
the same multi handle at the same time*. However, the `multi->xfers` table
reuses `mid` values from previous transfers that have been removed.

`multi->xfers` is created with an initial capacity. At the time of this
writing that is `16` for "multi_easy" handles (used in `curl_easy_perform()`
and `512` for multi handles created with `curl_multi_init()`.

The first added easy handle gets `mid == 1` assigned. The second one receives `2`,
even when the fist one has been removed already. Every added handle gets an
`mid` one larger than the previously assigned one. Until the capacity of
the table is reached and it starts looking for a free id at `1` again (`0`
is always in the table).

When adding a new handle, the multi checks the amount of free entries
in the `multi->xfers` table. If that drops below a threshold (currently 25%),
the table is resized. This serves two purposes: one, a previous `mid` is not
reused immediately and second, table resizes are not needed that often.

The table is implemented in `uint-table.[ch]`. More details in [`UINT_SETS`](UINT_SETS.md).

### Tracking `mid`s

There are several places where transfers need to be tracked:

* the multi tracks `process`, `pending` and `msgsent` transfers. A transfer
  is in at most one of these at a time.
* connections track the transfers that are *attached* to them.
* multi event handling tracks transfers interested in a specific socket.
* DoH handles track the handle they perform lookups for (and vice versa).

There are two bitset implemented for storing `mid`s: `uint_bset` and `uint_spbset`.
The first is a bitset optimal for storing a large number of unsigned int values.
The second one is a "sparse" variant good for storing a small set of numbers.
More details about these in [`UINT_SETS`](UINT_SETS.md).

A multi uses `uint_bset`s for `process`, `pending` and `msgsent`. Connections
and sockets use the sparse variant as both often track only a single transfer
and at most 100 on an HTTP/2 or HTTP/3 connection/socket.

These sets allow safe iteration while being modified. This allows a multi
to iterate over its "process" set while existing transfers are removed
or new ones added.
