---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_pause
Section: 3
Source: libfetch
See-also:
  - fetch_easy_cleanup (3)
  - fetch_easy_reset (3)
Protocol:
  - All
Added-in: 7.18.0
---

# NAME

fetch_easy_pause - pause and unpause a connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_pause(FETCH *handle, int bitmask );
~~~

# DESCRIPTION

Using this function, you can explicitly mark a running connection to get
paused, and you can unpause a connection that was previously paused. Unlike
most other libfetch functions, fetch_easy_pause(3) can be used from within
callbacks.

A connection can be paused by using this function or by letting the read or
the write callbacks return the proper magic return code
(*FETCH_READFUNC_PAUSE* and *FETCH_WRITEFUNC_PAUSE*). A write callback
that returns pause signals to the library that it could not take care of any
data at all, and that data is then delivered again to the callback when the
transfer is unpaused.

While it may feel tempting, take care and notice that you cannot call this
function from another thread. To unpause, you may for example call it from the
progress callback (FETCHOPT_PROGRESSFUNCTION(3)).

When this function is called to unpause receiving, the write callback might
get called before this function returns to deliver cached content. When
libfetch delivers such cached data to the write callback, it is delivered as
fast as possible, which may overstep the boundary set in
FETCHOPT_MAX_RECV_SPEED_LARGE(3) etc.

The **handle** argument identifies the transfer you want to pause or
unpause.

A paused transfer is excluded from low speed cancels via the
FETCHOPT_LOW_SPEED_LIMIT(3) option and unpausing a transfer resets the
time period required for the low speed limit to be met.

The **bitmask** argument is a set of bits that sets the new state of the
connection. The following bits can be used:

## FETCHPAUSE_RECV

Pause receiving data. There is no data received on this connection until this
function is called again without this bit set. Thus, the write callback
(FETCHOPT_WRITEFUNCTION(3)) is not called.

## FETCHPAUSE_SEND

Pause sending data. There is no data sent on this connection until this
function is called again without this bit set. Thus, the read callback
(FETCHOPT_READFUNCTION(3)) is not called.

## FETCHPAUSE_ALL

Convenience define that pauses both directions.

## FETCHPAUSE_CONT

Convenience define that unpauses both directions.

# LIMITATIONS

The pausing of transfers does not work with protocols that work without
network connectivity, like FILE://. Trying to pause such a transfer, in any
direction, might cause problems or error.

# MULTIPLEXED

When a connection is used multiplexed, like for HTTP/2, and one of the
transfers over the connection is paused and the others continue flowing,
libfetch might end up buffering contents for the paused transfer. It has to do
this because it needs to drain the socket for the other transfers and the
already announced window size for the paused transfer allows the server to
continue sending data up to that window size amount. By default, libfetch
announces a 32 megabyte window size, which thus can make libfetch end up
buffering 32 megabyte of data for a paused stream.

When such a paused stream is unpaused again, any buffered data is delivered
first.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* pause a transfer in both directions */
    fetch_easy_pause(fetch, FETCHPAUSE_RECV | FETCHPAUSE_SEND);

  }
}
~~~

# MEMORY USE

When pausing a download transfer by returning the magic return code from a
write callback, the read data is already in libfetch's internal buffers so it
has to keep it in an allocated buffer until the receiving is again unpaused
using this function.

If the downloaded data is compressed and is asked to get uncompressed
automatically on download, libfetch continues to uncompress the entire
downloaded chunk and it caches the data uncompressed. This has the side-
effect that if you download something that is compressed a lot, it can result
in a large data amount needing to be allocated to save the data during the
pause. Consider not using paused receiving if you allow libfetch to uncompress
data automatically.

If the download is done with HTTP/2 or HTTP/3, there is up to a stream window
size worth of data that fetch cannot stop but instead needs to cache while the
transfer is paused. This means that if a window size of 64 MB is used, libfetch
might end up having to cache 64 MB of data.

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
