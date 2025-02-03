---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTPGET
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_NOBODY (3)
  - FETCHOPT_POST (3)
  - FETCHOPT_UPLOAD (3)
  - fetch_easy_reset (3)
Added-in: 7.8.1
---

# NAME

FETCHOPT_HTTPGET - ask for an HTTP GET request

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTPGET, long useget);
~~~

# DESCRIPTION

Pass a long. If *useget* is 1, this forces the HTTP request to get back to
using GET. Usable if a POST, HEAD, PUT, etc has been used previously using the
same fetch *handle*.

When setting FETCHOPT_HTTPGET(3) to 1, libfetch automatically sets
FETCHOPT_NOBODY(3) to 0 and FETCHOPT_UPLOAD(3) to 0.

Setting this option to zero has no effect. Applications need to explicitly
select which HTTP request method to use, they cannot deselect a method. To
reset a handle to default method, consider fetch_easy_reset(3).

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* use a GET to fetch this */
    fetch_easy_setopt(fetch, FETCHOPT_HTTPGET, 1L);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
