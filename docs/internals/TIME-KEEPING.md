<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Keeping Time

Transfers need the current time to handle timeouts and keep a record of
events. The current time function is `curlx_now()` and it uses a **monotonic**
clock on most platforms. This ensures that time only ever increases (the
timestamps it gives are however not the "real" world clock).

## Initial Approach (now historic)

The loop processing functions called `curlx_now()` at the beginning and then
passed a pointer to the `struct curltime now` to functions to save them the
calls. Passing this pointer down to all functions possibly involved was not
done as this pollutes the internal APIs.

So, some functions continued to call `curlx_now()` on their own while others
used the passed pointer *to a timestamp in the past*. This led to a transfer
experiencing *jumps* in time, reversing cause and effect. On fast systems,
this was mostly not noticeable. On slow machines or in CI, this led to rare
and annoying test failures.

(Especially when we added assertions that the reported "timeline" of a
transfer was in the correct order: *queue -> nameloopup -> connect ->
appconnect ->...*.)

## Revised Approach

The strategy of handling transfer's time is now:

* Keep a "now" timestamp in the multi handle. Keep a fallback "now" timestamp
  in the easy handle.
* Always use `Curl_pgrs_now(data)` to get the current time of a transfer.
* Do not use `curlx_now()` directly for transfer handling (exceptions apply
  for loops).

This has the following advantages:

* No need to pass a `struct curltime` around or pass a pointer to an outdated
  timestamp to other functions.
* No need to calculate the exact `now` until it is really used.
* Passing a `const` pointer is better than struct passing. Updating and
  passing a pointer to the same memory location for all transfers is even
  better.

Caveats:

* do not store the pointer returned by `Curl_pgrs_now(data)` anywhere that
  outlives the current code invocation.
