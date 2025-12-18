<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# `llist` - linked lists

    #include "llist.h"

This is the internal module for linked lists. The API is designed to be
flexible but also to avoid dynamic memory allocation.

None of the involved structs should be accessed using struct fields (outside
of `llist.c`). Use the functions.

## Setup and shutdown

`struct Curl_llist` is the struct holding a single linked list. It needs to be
initialized with a call to `Curl_llist_init()` before it can be used

To clean up a list, call `Curl_llist_destroy()`. Since the linked lists
themselves do not allocate memory, it can also be fine to just *not* clean up
the list.

## Add a node

There are two functions for adding a node to a linked list:

1. Add it last in the list with `Curl_llist_append`
2. Add it after a specific existing node with `Curl_llist_insert_next`

When a node is added to a list, it stores an associated custom pointer to
anything you like and you provide a pointer to a `struct Curl_llist_node`
struct in which it stores and updates pointers. If you intend to add the same
struct to multiple lists concurrently, you need to have one `struct
Curl_llist_node` for each list.

Add a node to a list with `Curl_llist_append(list, elem, node)`. Where

- `list`: points to a `struct Curl_llist`
- `elem`: points to what you want added to the list
- `node`: is a pointer to a `struct Curl_llist_node`. Data storage for this
  node.

Example: to add a `struct foobar` to a linked list. Add a node struct within
it:

    struct foobar {
       char *random;
       struct Curl_llist_node storage; /* can be anywhere in the struct */
       char *data;
    };

    struct Curl_llist barlist; /* the list for foobar entries */
    struct foobar entries[10];

    Curl_llist_init(&barlist, NULL);

    /* add the first struct to the list */
    Curl_llist_append(&barlist, &entries[0], &entries[0].storage);

See also `Curl_llist_insert_next`.

## Remove a node

Remove a node again from a list by calling `Curl_llist_remove()`. This
destroys the node's `elem` (e.g. calling a registered free function).

To remove a node without destroying its `elem`, use `Curl_node_take_elem()`
which returns the `elem` pointer and removes the node from the list. The
caller then owns this pointer and has to take care of it.

## Iterate

To iterate over a list: first get the head entry and then iterate over the
nodes as long there is a next. Each node has an *element* associated with it,
the custom pointer you stored there. Usually a struct pointer or similar.

     struct Curl_llist_node *iter;

     /* get the first entry of the 'barlist' */
     iter = Curl_llist_head(&barlist);

     while(iter) {
       /* extract the element pointer from the node */
       struct foobar *elem = Curl_node_elem(iter);

       /* advance to the next node in the list */
       iter = Curl_node_next(iter);
     }

# Function overview

## `Curl_llist_init`

~~~c
void Curl_llist_init(struct Curl_llist *list, Curl_llist_dtor dtor);
~~~

Initializes the `list`. The argument `dtor` is NULL or a function pointer that
gets called when list nodes are removed from this list.

The function is infallible.

~~~c
typedef void (*Curl_llist_dtor)(void *user, void *elem);
~~~

`dtor` is called with two arguments: `user` and `elem`. The first being the
`user` pointer passed in to `Curl_llist_remove()`or `Curl_llist_destroy()` and
the second is the `elem` pointer associated with removed node. The pointer
that `Curl_node_elem()` would have returned for that node.

## `Curl_llist_destroy`

~~~c
void Curl_llist_destroy(struct Curl_llist *list, void *user);
~~~

This removes all nodes from the `list`. This leaves the list in a cleared
state.

The function is infallible.

## `Curl_llist_append`

~~~c
void Curl_llist_append(struct Curl_llist *list,
                       const void *elem, struct Curl_llist_node *node);
~~~

Adds `node` last in the `list` with a custom pointer to `elem`.

The function is infallible.

## `Curl_llist_insert_next`

~~~c
void Curl_llist_insert_next(struct Curl_llist *list,
                            struct Curl_llist_node *node,
                            const void *elem,
                            struct Curl_llist_node *node);
~~~

Adds `node` to the `list` with a custom pointer to `elem` immediately after
the previous list `node`.

The function is infallible.

## `Curl_llist_head`

~~~c
struct Curl_llist_node *Curl_llist_head(struct Curl_llist *list);
~~~

Returns a pointer to the first node of the `list`, or a NULL if empty.

## `Curl_node_uremove`

~~~c
void Curl_node_uremove(struct Curl_llist_node *node, void *user);
~~~

Removes the `node` the list it was previously added to. Passes the `user`
pointer to the list's destructor function if one was setup.

The function is infallible.

## `Curl_node_remove`

~~~c
void Curl_node_remove(struct Curl_llist_node *node);
~~~

Removes the `node` the list it was previously added to. Passes a NULL pointer
to the list's destructor function if one was setup.

The function is infallible.

## `Curl_node_elem`

~~~c
void *Curl_node_elem(struct Curl_llist_node *node);
~~~

Given a list node, this function returns the associated element.

## `Curl_node_next`

~~~c
struct Curl_llist_node *Curl_node_next(struct Curl_llist_node *node);
~~~

Given a list node, this function returns the next node in the list.
