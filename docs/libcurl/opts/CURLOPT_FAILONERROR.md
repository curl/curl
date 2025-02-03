---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FAILONERROR
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_RESPONSE_CODE (3)
  - FETCHOPT_HTTP200ALIASES (3)
  - FETCHOPT_KEEP_SENDING_ON_ERROR (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

FETCHOPT_FAILONERROR - request failure on HTTP response \>= 400

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FAILONERROR, long fail);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to fail the request if the HTTP
code returned is equal to or larger than 400. The default action would be to
return the page normally, ignoring that code.

This method is not fail-safe and there are occasions where non-successful
response codes slip through, especially when authentication is involved
(response codes 401 and 407).

You might get some amounts of headers transferred before this situation is
detected, like when a "100-continue" is received as a response to a POST/PUT
and a 401 or 407 is received immediately afterwards.

When this option is used and an error is detected, it causes the connection to
get closed and *FETCHE_HTTP_RETURNED_ERROR* is returned.

# DEFAULT

0, do not fail on error

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_FAILONERROR, 1L);
    ret = fetch_easy_perform(fetch);
    if(ret == FETCHE_HTTP_RETURNED_ERROR) {
      /* an HTTP response error problem */
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
