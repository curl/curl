---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_NUM_CONNECTS
Section: 3
Source: libfetch
See-also:
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.12.3
---

# NAME

FETCHINFO_NUM_CONNECTS - get number of created connections

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_NUM_CONNECTS, long *nump);
~~~

# DESCRIPTION

Pass a pointer to a long to receive how many new connections libfetch had to
create to achieve the previous transfer (only the successful connects are
counted). Combined with FETCHINFO_REDIRECT_COUNT(3) you are able to know how
many times libfetch successfully reused existing connection(s) or not. See the
connection options of fetch_easy_setopt(3) to see how libfetch tries to make
persistent connections to save time.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      long connects;
      res = fetch_easy_getinfo(fetch, FETCHINFO_NUM_CONNECTS, &connects);
      if(!res)
        printf("It needed %ld connects\n", connects);
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
