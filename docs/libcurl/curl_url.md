---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_url
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FETCHU (3)
  - fetch_url_cleanup (3)
  - fetch_url_dup (3)
  - fetch_url_get (3)
  - fetch_url_set (3)
  - fetch_url_strerror (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

fetch_url - create a URL handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHU *fetch_url();
~~~

# DESCRIPTION

This function allocates a URL object and returns a *FETCHU* handle for it,
to be used as input to all other URL API functions.

This is a handle to a URL object that holds or can hold URL components for a
single URL. When the object is first created, there is of course no components
stored. They are then set in the object with the fetch_url_set(3)
function.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHUcode rc;
  FETCHU *url = fetch_url();
  rc = fetch_url_set(url, FETCHUPART_URL, "https://example.com", 0);
  if(!rc) {
    char *scheme;
    rc = fetch_url_get(url, FETCHUPART_SCHEME, &scheme, 0);
    if(!rc) {
      printf("the scheme is %s\n", scheme);
      fetch_free(scheme);
    }
    fetch_url_cleanup(url);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns a **FETCHU *** if successful, or NULL if out of memory.
