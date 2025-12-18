<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# Multi Event Based

A libcurl multi is operating "event based" when the application uses
and event library like `libuv` to monitor the sockets and file descriptors
libcurl uses to trigger transfer operations. How that works from the
applications point of view is described in libcurl-multi(3).

This documents is about the internal handling.

## Source Locations

All code related to event based handling is found in `lib/multi_ev.c`
and `lib/multi_ev.h`. The header defines a set of internal functions
and `struct curl_multi_ev` that is embedded in each multi handle.

There is `Curl_multi_ev_init()` and `Curl_multi_ev_cleanup()` to manage
the overall life cycle, call on creation and destruction of the multi
handle.

## Tracking Events

First, the various functions in `lib/multi_ev.h` only ever really do
something when the libcurl application has registered its callback
in `multi->socket_cb`.

This is important as this callback gets informed about *changes* to sockets.
When a new socket is added, an existing is removed, or the `POLLIN/OUT`
flags change, `multi->socket_cb` needs to be invoked. `multi_ev` has to
track what it already reported to detect changes.

Most applications are expected to go "event based" right from the start,
but the libcurl API does not prohibit an application to start another
way and then go for events later on, even in the middle of a transfer.

### Transfer Events

Most event that happen are in connection with a transfer. A transfer
opens a connection, which opens a socket, and waits for this socket
to become writable (`POLLOUT`) when using TCP, for example.

The multi then calls `Curl_multi_ev_assess_xfer(multi, data)` to
let the multi event code detect what sockets the transfer is interested in.
If indeed a `multi->socket_cb` is set, the *current* transfer pollset is
retrieved via `Curl_multi_getsock()`. This current pollset is then
compared to the *previous* pollset. If relevant changes are detected,
`multi->socket_cb` gets informed about those. These can be:

 * a socket is in the current set, but not the previous one
 * a socket was also in the previous one, but IN/OUT flags changed
 * a socket in the previous one is no longer part of the current

`multi_ev.c` keeps a `struct mev_sh_entry` for each sockets in a hash
with the socket as key. It tracks in each entry which transfers are
interested in this particular socket. How many transfer want to read
and/or write and what the summarized `POLLIN/POLLOUT` action, that
had been reported to `multi->socket_cb` was.

This is necessary as a socket may be in use by several transfers
at the same time (think HTTP/2 on the same connection). When a transfer
is done and gets removed from the socket entry, it decrements
the reader and/or writer count (depending on what it was last
interested in). This *may* result in the entry's summarized action
to change, or not.

### Connection Events

There are also events not connected to any transfer that need to be tracked.
The multi connection cache, concerned with clean shutdowns of connections,
is interested in socket events during the shutdown.

To allow use of the libcurl infrastructure, the connection cache operates
using an *internal* easy handle that is not a transfer as such. The
internal handle is used for all connection shutdown operations, being tied
to a particular connection only for a short time. This means tracking
the last pollset for an internal handle is useless.

Instead, the connection cache uses `Curl_multi_ev_assess_conn()` to have
multi event handling check the connection and track a "last pollset"
for the connection alone.

## Event Processing

When the libcurl application is informed by the event library that
a particular socket has an event, it calls `curl_multi_socket_action()`
to make libcurl react to it. This internally invokes
`Curl_multi_ev_expire_xfers()` which expires all transfers that
are interested in the given socket, so the multi handle runs them.

In addition `Curl_multi_ev_expire_xfers()` returns a `bool` to let
the multi know that connections are also interested in the socket, so
the connection pool should be informed as well.

## All Things Pass

When a transfer is done, e.g. removed from its multi handle, the
multi calls `Curl_multi_ev_xfer_done()`. This cleans up the pollset
tracking for the transfer.

When a connection is done, and before it is destroyed,
`Curl_multi_ev_conn_done()` is called. This cleans up the pollset
tracking for this connection.

When a socket is about to be closed, `Curl_multi_ev_socket_done()`
is called to cleanup the socket entry and all information kept there.

These calls do not have to happen in any particular order. A transfer's
socket may be around while the transfer is ongoing. Or it might disappear
in the middle of things. Also, a transfer might be interested in several
sockets at the same time (resolving, eye balling, ftp are all examples of
those).

### And Come Again

While transfer and connection identifier are practically unique in a
libcurl application, sockets are not. Operating systems are keen on reusing
their resources, and the next socket may get the same identifier as
one just having been closed with high likelihood.

This means that multi event handling needs to be informed *before* a close,
clean up all its tracking and be ready to see that same socket identifier
again right after.
