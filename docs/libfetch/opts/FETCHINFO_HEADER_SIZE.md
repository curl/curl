---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_HEADER_SIZE
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REQUEST_SIZE (3)
  - FETCHINFO_SIZE_DOWNLOAD (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

FETCHINFO_HEADER_SIZE - get size of retrieved headers

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_HEADER_SIZE, long *sizep);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the total size of all the headers
received. Measured in number of bytes.

The total includes the size of any received headers suppressed by
FETCHOPT_SUPPRESS_CONNECT_HEADERS(3).

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
      long size;
      res = fetch_easy_getinfo(fetch, FETCHINFO_HEADER_SIZE, &size);
      if(!res)
        printf("Header size: %ld bytes\n", size);
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
