---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_PRETRANSFER_TIME
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CONNECT_TIME_T (3)
  - FETCHINFO_PRETRANSFER_TIME_T (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

FETCHINFO_PRETRANSFER_TIME - get the time until the file transfer start

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_PRETRANSFER_TIME,
                           double *timep);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the time, in seconds, it took from the
start until the file transfer is just about to begin.

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
    double pretransfer;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      res = fetch_easy_getinfo(fetch, FETCHINFO_PRETRANSFER_TIME, &pretransfer);
      if(FETCHE_OK == res) {
        printf("Time: %.1f", pretransfer);
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
