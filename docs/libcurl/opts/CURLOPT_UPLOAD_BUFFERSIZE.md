---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_UPLOAD_BUFFERSIZE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_BUFFERSIZE (3)
  - FETCHOPT_READFUNCTION (3)
  - FETCHOPT_TCP_NODELAY (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

FETCHOPT_UPLOAD_BUFFERSIZE - upload buffer size

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_UPLOAD_BUFFERSIZE, long size);
~~~

# DESCRIPTION

Pass a long specifying your preferred *size* (in bytes) for the upload
buffer in libfetch. It makes libfetch uses a larger buffer that gets passed to
the next layer in the stack to get sent off. In some setups and for some
protocols, there is a huge performance benefit of having a larger upload
buffer.

This is just treated as a request, not an order. You cannot be guaranteed to
actually get the given size.

The upload buffer size is by default 64 kilobytes. The maximum buffer size
allowed to be set is 2 megabytes. The minimum buffer size allowed to be set is
16 kilobytes.

The upload buffer is allocated on-demand - so if the handle is not used for
upload, this buffer is not allocated at all.

DO NOT set this option on a handle that is currently used for an active
transfer as that may lead to unintended consequences.

# DEFAULT

65536 bytes

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com/foo.bin");

    /* ask libfetch to allocate a larger upload buffer */
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD_BUFFERSIZE, 120000L);

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
