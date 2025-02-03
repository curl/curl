---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_SPEED_UPLOAD
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_SPEED_DOWNLOAD_T (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

FETCHINFO_SPEED_UPLOAD - get upload speed

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_SPEED_UPLOAD, double *speed);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the average upload speed that fetch
measured for the complete upload. Measured in bytes/second.

FETCHINFO_SPEED_UPLOAD_T(3) is a newer replacement that returns a more
sensible variable type.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* Perform the request */
    res = fetch_easy_perform(fetch);

    if(!res) {
      double speed;
      res = fetch_easy_getinfo(fetch, FETCHINFO_SPEED_UPLOAD, &speed);
      if(!res) {
        printf("Upload speed %.0f bytes/sec\n", speed);
      }
    }
  }
}
~~~

# DEPRECATED

Deprecated since 7.55.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
