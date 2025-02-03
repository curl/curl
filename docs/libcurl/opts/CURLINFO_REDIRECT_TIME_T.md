---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_REDIRECT_TIME_T
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REDIRECT_COUNT (3)
  - FETCHINFO_REDIRECT_TIME (3)
  - FETCHINFO_REDIRECT_URL (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.61.0
---

# NAME

FETCHINFO_REDIRECT_TIME_T - get the time for all redirection steps

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_REDIRECT_TIME_T,
                           fetch_off_t *timep);
~~~

# DESCRIPTION

Pass a pointer to a fetch_off_t to receive the total time, in microseconds, it
took for all redirection steps include name lookup, connect, pretransfer and
transfer before final transaction was started.
FETCHINFO_REDIRECT_TIME_T(3) holds the complete execution time for
multiple redirections.

See also the TIMES overview in the fetch_easy_getinfo(3) man page.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_off_t redirect;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      res = fetch_easy_getinfo(fetch, FETCHINFO_REDIRECT_TIME_T, &redirect);
      if(FETCHE_OK == res) {
        printf("Time: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld", redirect / 1000000,
               (long)(redirect % 1000000));
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
