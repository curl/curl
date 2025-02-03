---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_POSTTRANSFER_TIME_T
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PRETRANSFER_TIME_T (3)
  - FETCHOPT_TIMEOUT (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 8.10.0
---

# NAME

FETCHINFO_POSTTRANSFER_TIME_T - get the time until the last byte is sent

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_POSTTRANSFER_TIME_T,
                           fetch_off_t *timep);
~~~

# DESCRIPTION

Pass a pointer to a fetch_off_t to receive the time, in microseconds,
it took from the start until the last byte is sent by libfetch.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      fetch_off_t posttransfer;
      res = fetch_easy_getinfo(fetch, FETCHINFO_POSTTRANSFER_TIME_T,
                              &posttransfer);
      if(FETCHE_OK == res) {
        printf("Request sent after: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld us",
               posttransfer / 1000000, (long)(posttransfer % 1000000));
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
