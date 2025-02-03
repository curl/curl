---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_duphandle
Section: 3
Source: libfetch
See-also:
  - fetch_easy_cleanup (3)
  - fetch_easy_init (3)
  - fetch_easy_reset (3)
  - fetch_global_init (3)
Protocol:
  - All
Added-in: 7.9
---

# NAME

fetch_easy_duphandle - clone an easy handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCH *fetch_easy_duphandle(FETCH *handle);
~~~

# DESCRIPTION

This function returns a new fetch handle, a duplicate, using all the options
previously set in the input fetch *handle*. Both handles can subsequently be
used independently and they must both be freed with fetch_easy_cleanup(3).

Any options that the input handle has been told to point to (as opposed to
copy) with previous calls to fetch_easy_setopt(3), are pointed to by the new
handle as well. You must therefore make sure to keep the data around until
both handles have been cleaned up.

The new handle does **not** inherit any state information, no connections, no
SSL sessions and no cookies. It also does not inherit any share object states
or options (created as if FETCHOPT_SHARE(3) was set to NULL).

If the source handle has HSTS or alt-svc enabled, the duplicate gets data read
data from the main filename to populate the cache.

In multi-threaded programs, this function must be called in a synchronous way,
the input handle may not be in use when cloned.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    FETCH *nother;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    nother = fetch_easy_duphandle(fetch);
    res = fetch_easy_perform(nother);
    fetch_easy_cleanup(nother);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

If this function returns NULL, something went wrong and no valid handle was
returned.
