---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_url_dup
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FETCHU (3)
  - fetch_url (3)
  - fetch_url_cleanup (3)
  - fetch_url_get (3)
  - fetch_url_set (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

fetch_url_dup - duplicate a URL handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHU *fetch_url_dup(const FETCHU *inhandle);
~~~

# DESCRIPTION

Duplicates the URL object the input *FETCHU* *inhandle* identifies and
returns a pointer to the copy as a new *FETCHU* handle. The new handle also
needs to be freed with fetch_url_cleanup(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHUcode rc;
  FETCHU *url = fetch_url();
  FETCHU *url2;
  rc = fetch_url_set(url, FETCHUPART_URL, "https://example.com", 0);
  if(!rc) {
    url2 = fetch_url_dup(url); /* clone it */
    fetch_url_cleanup(url2);
  }
  fetch_url_cleanup(url);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns a pointer to a new `FETCHU` handle or NULL if out of memory.
