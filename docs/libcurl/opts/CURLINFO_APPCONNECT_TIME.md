---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_APPCONNECT_TIME
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_APPCONNECT_TIME_T (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.19.0
---

# NAME

FETCHINFO_APPCONNECT_TIME - get the time until the SSL/SSH handshake is completed

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_APPCONNECT_TIME,
                           double *timep);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the time, in seconds, it took from the
start until the SSL/SSH connect/handshake to the remote host was completed.
This time is most often close to the FETCHINFO_PRETRANSFER_TIME(3) time, except
for cases such as HTTP multiplexing where the pretransfer time can be delayed
due to waits in line for the stream and more.

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
    double connect;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      res = fetch_easy_getinfo(fetch, FETCHINFO_APPCONNECT_TIME, &connect);
      if(FETCHE_OK == res) {
        printf("Time: %.1f", connect);
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
