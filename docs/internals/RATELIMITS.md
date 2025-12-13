<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Rate Limiting Transfers

Rate limiting a transfer means that no more than "n bytes per second"
shall be sent or received. It can be set individually for both directions
via `CURLOPT_MAX_RECV_SPEED_LARGE` and `CURLOPT_MAX_SEND_SPEED_LARGE`. These
options may be adjusted for an ongoing transfer.

### Implementation Base

`ratelimit.[ch]` implements `struct Curl_rlimit` and functions to manage
such limits. It has the following properties:

* `rate_per_sec`: how many "tokens" can be used per second, 0 for infinite.
* `tokens`: the currently available tokens to consume
* `burst_per_sec`: an upper limit on tokens available
* `ts`: the microsecond timestamp of the last tokens update
* `spare_us`: elapsed microseconds that have not counted yet for a token update
* `blocked`: if the limit is blocked

Tokens can be *drained* from an `rlimit`. This reduces `tokens`, even to
negative values. To enforce the limits, tokens should not be drained
further when they reach 0, but such things may happen.

An `rlimit`can be asked how long to wait until `tokens` are positive again.
This is given in milliseconds. When token are available, this wait
time is 0.

Ideally a user of `rlimit` would consume the available tokens to 0, then
get a wait times of 1000ms, after which the set rate of tokens has
regenerated. Rinse and repeat.

Should a user drain twice the amount of the rate, tokens are negative
and the wait time is 2 seconds. The `spare_us` account for the
time that has passed for the consumption. When a user takes 250ms to
consume the rate, the wait time is then 750ms.

When a user drains nothing for two seconds, the available tokens would
grow to twice the rate, unless a burst rate is set.

Finally, an `rlimit` may be set to `blocked` and later unblocked again.
A blocked `rlimit` has no tokens available. This works also when the rate
is unlimited (`rate_per_sec` set to 0).

### Downloads

`rlimit` is in `data->progress.dl.rlimit`. `setopt.c` initializes it whenever
the application sets `CURLOPT_MAX_RECV_SPEED_LARGE`. This may be done
in the middle of a transfer.

`rlimit` tokens are drained in the "protocol" client writer. Checks for
capacity depend on the protocol:

* HTTP and other plain protocols: `transfer.c:sendrecv_dl()` reads only
up to capacity.
* HTTP/2: capacity is used to adjust a stream's window size. Since all
streams start with `64kb`, `rlimit` takes a few seconds to take effect.
* HTTP/3: ngtcp2 acknowledges stream data according to capacity. It
keeps track of bytes not acknowledged yet. This has the same effect as HTTP/2
window sizes.

(The quiche API does not offer control of `ACK`s and `rlimits` for download
do not work in that backend.)

### Uploads

`rlimit` is in `data->progress.ul.rlimit`. `setopt.c` initializes it whenever
the application sets `CURLOPT_MAX_SEND_SPEED_LARGE`. This may be done
in the middle of a transfer.

The upload capacity is checked in `Curl_client_read()` and readers are
only asked to read bytes up to the `rlimit` capacity. This limits upload
of data for all protocols in the same way.

### Pause/Unpause

Pausing of up-/downloads sets the corresponding `rlimit` to blocked. Unpausing
removes that block.

### Suspending transfers

While obeying the `rlimit` for up-/download leads to the desired transfer
rates, the other issue that needs care is CPU consumption.

`rlimits` are inspected when computing the "pollset" of a transfer. When
a transfer wants to send, but not send tokens are available, the `POLLOUT`
is removed from the pollset. Same for receiving.

For a transfer that is, due to `rlimit`, not able to progress, the pollset
is then empty. No socket events are monitored, no CPU activity
happens. For paused transfers, this is sufficient.

Draining `rlimit` happens when a transfer is in `PERFORM` state and
exhausted limits cause the timer `TOOFAST` to be set. When the fires,
the transfer runs again and `rlimit`s are re-evaluated.
