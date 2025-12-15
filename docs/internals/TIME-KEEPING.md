<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Keeping Time

Transfers need the current time to handle timeouts and keep a record of events. The current
time function is `curlx_now()` and it uses a **monotonic** clock on most platforms. This
ensures that time only ever increases (the timestamps it gives are however not the "real"
world clock).

The simplest handling of transfer time would be to just always call `curlx_now()`. However
there is a performance penalty to that - varying by platform - so this is not a desirable
strategy. Processing thousands of transfers in a loop needs a smarter approach.

## Initial Approach (now historic)

The loop processing functions called `curlx_now()` at the beginning and then passed
a pointer to the `struct curltime now` to functions to save them the calls. Passing
this pointer down to all functions possibly involved was not done as this pollutes
the internal APIs.

So, some functions continued to call `curlx_now()` on their own while others used the
passed pointer *to a timestamp in the past*. This led to a transfer experiencing *jumps*
in time, reversing cause and effect. On fast systems, this was mostly not noticeable. On
slow machines or in CI, this led to rare and annoying test failures.

(Especially when we added assertions that the reported "timeline" of a transfer was
in the correct order: *queue -> nameloopup -> connect -> appconnect ->...*.)

## Revised Approach

The strategy of handling transfer's time is now:

* Keep a "now" timestamp in `data->progress.now`.
* Perform time checks and event recording using `data->progress.now`.
* Set `data->progress.now` at the start of API calls (e.g. `curl_multi_perform()`, etc.).
* Set `data->progress.now` when recorded events happen (for precision).
* Set `data->progress.now` on multi state changes.
* Set `data->progress.now` in `pingpong` timeout handling, since `pingpong` is old and not always non-blocking.

In addition to *setting* `data->progress.now` this timestamp can be *advanced* using 2 new methods:

* `Curl_pgrs_now_at_least(data, &now)`: code that has a "now" timestamp can progress the `data`'s own "now" to be at least as new. If `data->progress.now` is already newer, no change is done. A transfer never goes **back**.
* `Curl_pgrs_now_update(data1, data2)`: update the "now" in `data1` to be at least as new as the one in `data2`. If it already is newer, nothing changes.

### Time Advancing Loops

This advancing is used in the following way in loop like `curl_multi_perform()`:

```C
struct curltime now = curlx_now(); /* start of API call */
forall data in transfers {
  Curl_pgrs_set_at_least(data, now);
  progress(data);   /* may update "now" */
  now = data->progress.now;
}
```

Transfers that update their "now" pass that timestamp to the next transfer processed.

### Transfers triggering other transfers

In HTTP/2 and HTTP/3 processing, incoming data causes actions on transfers other than
the calling one. The protocols may receive data for any transfer on the connection and need
to dispatch it:

* a Close/Reset comes in for another transfer. That transfer is marked as "dirty", making sure it is processed in a timely manner.
* Response Data arrives: this data is written out to the client. Before this is done, the "now" timestamp is updated via `Curl_pgrs_now_update(data, calling)` from the "calling" transfer.

## Blocking Operations

We still have places in `libcurl` where we do blocking operations. We should always use `Curl_pgrs_now_set(data)` afterwards since we cannot be sure how much time has passed. Since loop processing passed an updated "now" to the next transfer, a delay due to blocking is passed on.

There are other places where we may lose track of time:

* Cache/Pool Locks: no "now" updates happen after a lock has been acquired. These locks should not be kept for a longer time.
* User Callbacks: no "now" updates happen after callbacks have been invoked. The expectation is that those do not take long.

Should these assumptions prove wrong, we need to add updates.
