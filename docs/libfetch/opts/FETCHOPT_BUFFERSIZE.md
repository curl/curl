---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_BUFFERSIZE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_MAXFILESIZE (3)
  - FETCHOPT_MAX_RECV_SPEED_LARGE (3)
  - FETCHOPT_UPLOAD_BUFFERSIZE (3)
  - FETCHOPT_WRITEFUNCTION (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

FETCHOPT_BUFFERSIZE - receive buffer size

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_BUFFERSIZE, long size);
~~~

# DESCRIPTION

Pass a long specifying your preferred *size* (in bytes) for the receive buffer
in libfetch. The main point of this would be that the write callback gets
called more often and with smaller chunks. Secondly, for some protocols, there
is a benefit of having a larger buffer for performance.

This is just treated as a request, not an order. You cannot be guaranteed to
actually get the given size.

This buffer size is by default *FETCH_MAX_WRITE_SIZE* (16kB). The maximum
buffer size allowed to be set is *FETCH_MAX_READ_SIZE* (10MB). The minimum
buffer size allowed to be set is 1024.

DO NOT set this option on a handle that is currently used for an active
transfer as that may lead to unintended consequences.

The maximum size was 512kB until 7.88.0.

Starting in libfetch 8.7.0, there is just a single transfer buffer allocated
per multi handle. This buffer is used by all easy handles added to a multi
handle no matter how many parallel transfers there are. The buffer remains
allocated as long as there are active transfers.

# DEFAULT

FETCH_MAX_WRITE_SIZE (16kB)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com/foo.bin");

    /* ask libfetch to allocate a larger receive buffer */
    fetch_easy_setopt(fetch, FETCHOPT_BUFFERSIZE, 120000L);

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
