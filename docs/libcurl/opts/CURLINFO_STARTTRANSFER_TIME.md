---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_STARTTRANSFER_TIME
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_STARTTRANSFER_TIME_T (3)
  - FETCHOPT_TIMEOUT (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.9.2
---

# NAME

FETCHINFO_STARTTRANSFER_TIME - get the time until the first byte is received

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_STARTTRANSFER_TIME,
                           double *timep);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the time, in seconds, it took from the
start until the first byte is received by libfetch. This includes
FETCHINFO_PRETRANSFER_TIME(3) and also the time the server needs to
calculate the result.

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
    double start;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      res = fetch_easy_getinfo(fetch, FETCHINFO_STARTTRANSFER_TIME, &start);
      if(FETCHE_OK == res) {
        printf("Time: %.1f", start);
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
