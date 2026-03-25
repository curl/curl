<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Thread Pool and Queue

The thread pool and queue manage asynchronous processing of "work items"
to a user. The "work items" are opaque to the pool and queue, represented
by a `void *`, handled via callback functions.

Thread pool and queue are available with `pthreads` or native Win32
builds.

## `Curl_thrdpool`

This data structure manages a pool of threads for asynchronous operations.

### Properties

A pool's properties are:

- minimum number of threads running, default 0
- maximum number of threads running
- timeout for idle threads before they shut down

The minimum number of threads is started at creation of the pool and
kept always running. On demand, when more work is available but all
existing threads are busy, it starts new threads, up to maximum.

When work ceases, the threads "above" the minimum number exit again
after the given idle time.

### Operation

The pool is created with providing three callback functions:

- `take`: the pool calls this to take a new "work item" for processing. From
   the pool's point of view, a work item is a `void *`. "take" is called from
   the pool's threads. When getting anything besides `NULL`, the thread is
   "busy". On getting `NULL`, the thread becomes idle.
- `process`: called by a pool thread to process a work item. This can not
   return any error. Any error handling must be done via properties in
   the work item itself, opaque to the pool.
- `return`: after processing, the work item is returned and the pool has
   no longer have any memory of it.

The pool only tries to "take" new work items when told to. Calling
`Curl_thrdpool_signal(pool, n)` awakens up to `n`threads which then
take new work items. This may cause new threads being started. The other
time a pool thread "take"s work it when it has finished
processing and returned another item.

A thread pool can be destroyed via `Curl_thrdpool_destroy(pool, join)` where
`join` determines if active threads shall be joined or detached.

### Safety

The thread pool operates use a mutex and condition variables to manage
concurrency. All interactions and callback invocation are done under
the pool's mutex lock, *except* the "process" callback which is invoked
unlocked.

To avoid deadlocks, no callback must invoked other pool functions. Also,
any call of pool functions may result in callback invocations.

The "work items", once "taken" by the pool, should not be referenced
from any other place. Thread pools **always** invoke the "return"
callback on a work item, even after the pool has been destroyed by
detaching the threads.

There is a `user_data` in the pool's creation that is passed to "take"
and "return" callbacks. Once a pool is destroyed, this `user_data` is
cleared and "return" callbacks always see a `NULL`. This way,
the "return" callback may act on that fact.

## `Curl_thrdq`

A `thrdq` is a two-way queue with a thread pool. Users of a thread queue may
"send" work items into the queue and "receive" processed items back.

### Properties

A queue's properties are:

- The properties of the thread pool to create
- the maximum length of the "send" queue, 0 for unlimited

### Operation

The queue is created with providing three callback functions:

- `free`: called to free a work item that is in the queue but is
  no longer returned (or processed). This happens when the queue is
  destroyed or when work items are removed for other reasons.
- `process`: process the item. Can not fail.
- `event`: called when work items have been added to the "receive" list.

Users of a thread queue call `Curl_thrdq_send()` to add a work item to
the queue. Calling `Curl_thrdq_recv()` delivers processed items back.

### Safety

The thread queue operates use a mutex and condition variables to manage
concurrency. All interactions and callback invocation are done under
the queue's mutex lock, *except* the "process" callback which is invoked
unlocked.

Users of a thread queue should not hold any reference to work items sent
into the queue. The provided "free" callback has to take care of any
resources allocated by work items.
