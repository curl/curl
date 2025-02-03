---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_LOCALPORT
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_LOCAL_PORT (3)
  - FETCHOPT_INTERFACE (3)
  - FETCHOPT_LOCALPORTRANGE (3)
Protocol:
  - All
Added-in: 7.15.2
---

# NAME

FETCHOPT_LOCALPORT - local port number to use for socket

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_LOCALPORT, long port);
~~~

# DESCRIPTION

Pass a long. This sets the local port number of the socket used for the
connection. This can be used in combination with FETCHOPT_INTERFACE(3)
and you are recommended to use FETCHOPT_LOCALPORTRANGE(3) as well when
this option is set. Valid port numbers are 1 - 65535.

# DEFAULT

0, disabled - use whatever the system thinks is fine

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
