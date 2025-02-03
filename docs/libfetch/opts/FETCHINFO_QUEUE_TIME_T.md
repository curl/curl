---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_QUEUE_TIME_T
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_STARTTRANSFER_TIME_T (3)
  - FETCHOPT_TIMEOUT (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 8.6.0
---

# NAME

FETCHINFO_QUEUE_TIME_T - time this transfer was queued

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_QUEUE_TIME_T,
                           fetch_off_t *timep);
~~~

# DESCRIPTION

Pass a pointer to a fetch_off_t to receive the time, in microseconds, this
transfer was held in a waiting queue before it started "for real". A transfer
might be put in a queue if after getting started, it cannot create a new
connection etc due to set conditions and limits imposed by the application.

See also the TIMES overview in the fetch_easy_getinfo(3) man page.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_off_t queue;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      res = fetch_easy_getinfo(fetch, FETCHINFO_QUEUE_TIME_T, &queue);
      if(FETCHE_OK == res) {
        printf("Queued: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld us", queue / 1000000,
               (long)(queue % 1000000));
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
