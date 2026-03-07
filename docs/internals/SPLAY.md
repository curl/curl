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

libcurl adds fixed timeout expiry timestamps to the splay tree, and is meant
to scale up to holding a huge amount of pending timeouts with decent
performance.

The splay tree is used to:

1. figure out the next timeout expiry value closest in time
2. iterate over timeouts that already have expired

This splay tree rebalances itself based on the time value.

Each node in the splay tree points to a `struct Curl_easy`. Each `Curl_easy`
struct is represented only once in the tree. To still allow each easy handle
to have a large number of timeouts per handle, each handle has a sorted linked
list of pending timeouts. Only the handle's timeout that is closest to expire
is the timestamp used for the splay tree node.

When a specific easy handle's timeout expires, the node gets removed from the
splay tree and from the handle's linked list of timeouts. The next timeout for
that handle is then first in line and becomes the new timeout value as the
node is re-added to the splay.

## `Curl_splay`

~~~c
struct Curl_tree *Curl_splay(struct curltime i, struct Curl_tree *t);
~~~

Rearranges the tree `t` after the provide time `i`.

## `Curl_splayinsert`

~~~c
struct Curl_tree *Curl_splayinsert(struct curltime key,
                                   struct Curl_tree *t,
                                   struct Curl_tree *node);
~~~

This function inserts a new `node` in the tree, using the given `key`
timestamp. The `node` struct has a field called `->payload` that can be set to
point to anything. libcurl sets this to the `struct Curl_easy` handle that is
associated with the timeout value set in `key`.

The splay insert function does not allocate any memory, it assumes the caller
has that arranged.

It returns a pointer to the new tree root.

## `Curl_splaygetbest`

~~~c
struct Curl_tree *Curl_splaygetbest(struct curltime key,
                                    struct Curl_tree *tree,
                                    struct Curl_tree **removed);
~~~

If there is a node in the `tree` that has a time value that is less than the
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
void Curl_splayset(struct Curl_tree *node, void *payload);
~~~

Set a custom pointer to be stored in the splay node. This pointer is not used
by the splay code itself and can be retrieved again with `Curl_splayget`.

## `Curl_splayget`

~~~c
void *Curl_splayget(struct Curl_tree *node);
~~~

Get the custom pointer from the splay node that was previously set with
`Curl_splayset`. If no pointer was set before, it returns NULL.
