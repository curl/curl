---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_VERBOSE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_ERRORBUFFER (3)
  - FETCHOPT_STDERR (3)
  - fetch_global_trace (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_VERBOSE - verbose mode

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_VERBOSE, long onoff);
~~~

# DESCRIPTION

Set the *onoff* parameter to 1 to make the library display a lot of
verbose information about its operations on this *handle*. Useful for
libfetch and/or protocol debugging and understanding. The verbose information
is sent to stderr, or the stream set with FETCHOPT_STDERR(3).

You hardly ever want this enabled in production use, you almost always want
this used when you debug/report problems.

To also get all the protocol data sent and received, consider using the
FETCHOPT_DEBUGFUNCTION(3).

# DEFAULT

0, meaning disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* ask libfetch to show us the verbose output */
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
