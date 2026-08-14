<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# `splay`

    #include "splay.h"

This is an internal module for splay tree management. A splay tree is a binary
search tree with the additional property that recently accessed elements are
quick to access again. A self-balancing tree.

Nodes are added to the tree, they are accessed and removed from the tree and
it automatically rebalances itself in each operation.

## libcurl use

libcurl adds fixed timeout expiry `timediff_t` to the splay tree, and is meant
to scale up to holding a huge amount of pending timeouts with decent
performance.

The splay tree is used to:

1. figure out the next timeout expiry value closest in time
2. iterate over timeouts that already have expired

This splay tree rebalances itself based on the timeout value.

Each node in the splay tree carries a `uint32_t id`. This is set to the
`mid`, the unique transfer identifier in a multi handle. Each transfer
is added only once in the tree. To still allow each transfer
to have a large number of timeouts per handle, each handle has a sorted list
of pending timeouts. Only the handle's timeout that is closest to expire
is the timestamp used for the splay tree node.

When a specific easy handle's timeout expires, the node gets removed from the
splay tree and from the handle's list of timeouts. The next timeout for
that handle is then first in line and becomes the new timeout value as the
node is re-added to the splay.

To convert the `timediff_t` is the splay to the correct timestamps, the
multi handle carries a "base timestamp", set once when created, and the
timeout values are calculated relative to that. This works for about
500,000 years of continued operation of a multi handle.

## `Curl_splay`

~~~c
struct Curl_tree *Curl_splay(struct curltime i, struct Curl_tree *t);
~~~

Rearranges the tree `t` after the provide time `i`.

## `Curl_splayinsert`

~~~c
struct Curl_tree *Curl_splayinsert(timediff_t key,
                                   struct Curl_tree *t,
                                   struct Curl_tree *node,
                                   uint32_t id);
~~~

This function inserts a new `node` in the tree, using the given `key`
timeout. The `node` struct has a field called `->id` which is set to
the passed `id`. libcurl sets this to the transfer's `mid`, the unique
identifier in a multi handle.

The splay insert function does not allocate any memory, it assumes the caller
has that arranged.

It returns a pointer to the new tree root.

## `Curl_splaygetbest`

~~~c
struct Curl_tree *Curl_splaygetbest(timediff_t key,
                                    struct Curl_tree *tree,
                                    struct Curl_tree **removed);
~~~

If there is a node in the `tree` that has a timeout that is less than the
provided `key`, this function removes that node from the tree and provides it
in the `*removed` pointer (or NULL if there was no match).

It returns a pointer to the new tree root.

## `Curl_splayremove`

~~~c
int Curl_splayremove(struct Curl_tree *tree,
                     struct Curl_tree *node,
                     struct Curl_tree **newroot);
~~~

Removes a given `node` from a splay `tree`, and returns the `newroot`
identifying the new tree root.

Note that a clean tree without any nodes present implies a NULL pointer.

## `Curl_splayset`

~~~c
void Curl_splayset(struct Curl_tree *node, uint32_t id);
~~~

Sets the `id` in the splay node. This value  is not used
by the splay code itself and can be retrieved again with `Curl_splayget`.

## `Curl_splayget`

~~~c
uint32_t Curl_splayget(struct Curl_tree *node);
~~~

Get the `id` from the splay node that was previously set.
