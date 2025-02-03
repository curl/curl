---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_PRETRANSFER_TIME_T
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CONNECT_TIME (3)
  - FETCHINFO_PRETRANSFER_TIME_T (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.61.0
---

# NAME

FETCHINFO_PRETRANSFER_TIME_T - get the time until the file transfer start

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_PRETRANSFER_TIME_T,
                           fetch_off_t *timep);
~~~

# DESCRIPTION

Pass a pointer to a fetch_off_t to receive the time, in microseconds, it took
from the start until the file transfer is just about to begin.

This time-stamp includes all pre-transfer commands and negotiations that are
specific to the particular protocol(s) involved. It includes the sending of
the protocol-specific instructions that trigger a transfer.

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
    fetch_off_t pretransfer;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      res = fetch_easy_getinfo(fetch, FETCHINFO_PRETRANSFER_TIME_T, &pretransfer);
      if(FETCHE_OK == res) {
        printf("Time: %" FETCH_FORMAT_FETCH_OFF_T ".%06ld\n",
               pretransfer / 1000000,
               (long)(pretransfer % 1000000));
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
