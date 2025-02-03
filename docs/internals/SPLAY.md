<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

# `splay`

    #include "splay.h"

This is an internal module for splay tree management. A splay tree is a binary
search tree with the additional property that recently accessed elements are
quick to access again. A self-balancing tree.

Nodes are added to the tree, they are accessed and removed from the tree and
it automatically rebalances itself in each operation.

## libfetch use

libfetch adds fixed timeout expiry timestamps to the splay tree, and is meant
to scale up to holding a huge amount of pending timeouts with decent
performance.

The splay tree is used to:

1. figure out the next timeout expiry value closest in time
2. iterate over timeouts that already have expired

This splay tree rebalances itself based on the time value.

Each node in the splay tree points to a `struct Fetch_easy`. Each `Fetch_easy`
struct is represented only once in the tree. To still allow each easy handle
to have a large number of timeouts per handle, each handle has a sorted linked
list of pending timeouts. Only the handle's timeout that is closest to expire
is the timestamp used for the splay tree node.

When a specific easy handle's timeout expires, the node gets removed from the
splay tree and from the handle's linked list of timeouts. The next timeout for
that handle is then first in line and becomes the new timeout value as the
node is re-added to the splay.

## `Fetch_splay`

~~~c
struct Fetch_tree *Fetch_splay(struct fetchtime i, struct Fetch_tree *t);
~~~

Rearranges the tree `t` after the provide time `i`.

## `Fetch_splayinsert`

~~~c
struct Fetch_tree *Fetch_splayinsert(struct fetchtime key,
                                   struct Fetch_tree *t,
                                   struct Fetch_tree *node);
~~~

This function inserts a new `node` in the tree, using the given `key`
timestamp. The `node` struct has a field called `->payload` that can be set to
point to anything. libfetch sets this to the `struct Fetch_easy` handle that is
associated with the timeout value set in `key`.

The splay insert function does not allocate any memory, it assumes the caller
has that arranged.

It returns a pointer to the new tree root.

## `Fetch_splaygetbest`

~~~c
struct Fetch_tree *Fetch_splaygetbest(struct fetchtime key,
                                    struct Fetch_tree *tree,
                                    struct Fetch_tree **removed);
~~~

If there is a node in the `tree` that has a time value that is less than the
provided `key`, this function removes that node from the tree and provides it
in the `*removed` pointer (or NULL if there was no match).

It returns a pointer to the new tree root.

## `Fetch_splayremove`

~~~c
int Fetch_splayremove(struct Fetch_tree *tree,
                     struct Fetch_tree *node,
                     struct Fetch_tree **newroot);
~~~

Removes a given `node` from a splay `tree`, and returns the `newroot`
identifying the new tree root.

Note that a clean tree without any nodes present implies a NULL pointer.

## `Fetch_splayset`

~~~c
void Fetch_splayset(struct Fetch_tree *node, void *payload);
~~~

Set a custom pointer to be stored in the splay node. This pointer is not used
by the splay code itself and can be retrieved again with `Fetch_splayget`.

## `Fetch_splayget`

~~~c
void *Fetch_splayget(struct Fetch_tree *node);
~~~

Get the custom pointer from the splay node that was previously set with
`Fetch_splayset`. If no pointer was set before, it returns NULL.
