---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_NAMELOOKUP_TIME
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_NAMELOOKUP_TIME_T (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

FETCHINFO_NAMELOOKUP_TIME - get the name lookup time

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_NAMELOOKUP_TIME,
                           double *timep);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the total time in seconds from the start
until the name resolving was completed.

When a redirect is followed, the time from each request is added together.

See also the TIMES overview in the fetch_easy_getinfo(3) man page.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    double namelookup;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      res = fetch_easy_getinfo(fetch, FETCHINFO_NAMELOOKUP_TIME, &namelookup);
      if(FETCHE_OK == res) {
        printf("Time: %.1f", namelookup);
      }
    }
    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
