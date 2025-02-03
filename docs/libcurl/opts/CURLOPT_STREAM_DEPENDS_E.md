---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_STREAM_DEPENDS_E
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_PIPELINING (3)
  - FETCHOPT_HTTP_VERSION (3)
  - FETCHOPT_STREAM_DEPENDS (3)
  - FETCHOPT_STREAM_WEIGHT (3)
Protocol:
  - HTTP
Added-in: 7.46.0
---

# NAME

FETCHOPT_STREAM_DEPENDS_E - stream this transfer depends on exclusively

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_STREAM_DEPENDS_E,
                          FETCH *dephandle);
~~~

# DESCRIPTION

Pass a `FETCH` pointer in *dephandle* to identify the stream within the same
connection that this stream is depending upon exclusively. That means it
depends on it and sets the Exclusive bit.

The spec says "Including a dependency expresses a preference to allocate
resources to the identified stream rather than to the dependent stream."

Setting a dependency with the exclusive flag for a reprioritized stream causes
all the dependencies of the new parent stream to become dependent on the
reprioritized stream.

This option can be set during transfer.

*dephandle* must not be the same as *handle*, that makes this function return
an error. It must be another easy handle, and it also needs to be a handle of
a transfer that is about to be sent over the same HTTP/2 connection for this
option to have an actual effect.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  FETCH *fetch2 = fetch_easy_init(); /* a second handle */
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/one");

    /* the second depends on the first */
    fetch_easy_setopt(fetch2, FETCHOPT_URL, "https://example.com/two");
    fetch_easy_setopt(fetch2, FETCHOPT_STREAM_DEPENDS_E, fetch);

    /* then add both to a multi handle and transfer them */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
