---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_REDIRECT_COUNT
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REDIRECT_URL (3)
  - FETCHOPT_FOLLOWLOCATION (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.9.7
---

# NAME

FETCHINFO_REDIRECT_COUNT - get the number of redirects

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_REDIRECT_COUNT,
                           long *countp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the total number of redirections that were
actually followed.

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
      long redirects;
      fetch_easy_getinfo(fetch, FETCHINFO_REDIRECT_COUNT, &redirects);
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
