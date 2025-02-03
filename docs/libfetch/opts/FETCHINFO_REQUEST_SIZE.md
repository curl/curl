---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_REQUEST_SIZE
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_HEADER_SIZE (3)
  - FETCHINFO_SIZE_DOWNLOAD_T (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

FETCHINFO_REQUEST_SIZE - get size of sent request

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_REQUEST_SIZE, long *sizep);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the total size of the issued
requests. This is so far only for HTTP requests. Note that this may be more
than one request if FETCHOPT_FOLLOWLOCATION(3) is enabled.

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
    if(res == FETCHE_OK) {
      long req;
      res = fetch_easy_getinfo(fetch, FETCHINFO_REQUEST_SIZE, &req);
      if(!res)
        printf("Request size: %ld bytes\n", req);
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
