---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_LOCALPORTRANGE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_INTERFACE (3)
  - FETCHOPT_LOCALPORT (3)
Protocol:
  - All
Added-in: 7.15.2
---

# NAME

FETCHOPT_LOCALPORTRANGE - number of additional local ports to try

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_LOCALPORTRANGE,
                          long range);
~~~

# DESCRIPTION

Pass a long. The *range* argument is the number of attempts libfetch makes
to find a working local port number. It starts with the given
FETCHOPT_LOCALPORT(3) and adds one to the number for each retry. Setting
this option to 1 or below makes libfetch only do one try for the exact port
number. Port numbers by nature are scarce resources that are busy at times so
setting this value to something too low might cause unnecessary connection
setup failures.

# DEFAULT

1

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");
    fetch_easy_setopt(fetch, FETCHOPT_LOCALPORT, 49152L);
    /* and try 20 more ports following that */
    fetch_easy_setopt(fetch, FETCHOPT_LOCALPORTRANGE, 20L);
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
