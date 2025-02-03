---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_HTTP_CONNECTCODE
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RESPONSE_CODE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.10.7
---

# NAME

FETCHINFO_HTTP_CONNECTCODE - get the CONNECT response code

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_HTTP_CONNECTCODE, long *p);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the last received HTTP proxy response code
to a CONNECT request. The returned value is zero if no such response code was
available.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* typically CONNECT is used to do HTTPS over HTTP proxies */
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://127.0.0.1");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      long code;
      res = fetch_easy_getinfo(fetch, FETCHINFO_HTTP_CONNECTCODE, &code);
      if(!res && code)
        printf("The CONNECT response code: %03ld\n", code);
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
