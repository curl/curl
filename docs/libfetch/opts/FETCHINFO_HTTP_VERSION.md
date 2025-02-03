---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_HTTP_VERSION
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RESPONSE_CODE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.50.0
---

# NAME

FETCHINFO_HTTP_VERSION - get the http version used in the connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_HTTP_VERSION, long *p);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the version used in the last http
connection done using this handle. The returned value is
FETCH_HTTP_VERSION_1_0, FETCH_HTTP_VERSION_1_1, FETCH_HTTP_VERSION_2_0,
FETCH_HTTP_VERSION_3 or 0 if the version cannot be determined.

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
      long http_version;
      fetch_easy_getinfo(fetch, FETCHINFO_HTTP_VERSION, &http_version);
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
