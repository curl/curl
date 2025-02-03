---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_PRIMARY_PORT
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_LOCAL_PORT (3)
  - FETCHINFO_PRIMARY_IP (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.21.0
---

# NAME

FETCHINFO_PRIMARY_PORT - get the latest destination port number

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_PRIMARY_PORT, long *portp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the destination port of the most recent
connection done with this **fetch** handle.

This is the destination port of the actual TCP or UDP connection libfetch used.
If a proxy was used for the most recent transfer, this is the port number of
the proxy, if no proxy was used it is the port number of the most recently
accessed URL.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      long port;
      res = fetch_easy_getinfo(fetch, FETCHINFO_PRIMARY_PORT, &port);
      if(!res)
        printf("Connected to remote port: %ld\n", port);
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
