---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTP09_ALLOWED
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_HTTP_VERSION (3)
  - FETCHOPT_SSLVERSION (3)
Added-in: 7.64.0
---

# NAME

FETCHOPT_HTTP09_ALLOWED - allow HTTP/0.9 response

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTP09_ALLOWED, long allowed);
~~~

# DESCRIPTION

Pass the long argument *allowed* set to 1L to allow HTTP/0.9 responses.

An HTTP/0.9 response is a server response entirely without headers and only a
body. You can connect to lots of random TCP services and still get a response
that fetch might consider to be HTTP/0.9.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_HTTP09_ALLOWED, 1L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

fetch allowed HTTP/0.9 responses by default before 7.66.0

Since 7.66.0, libfetch requires this option set to 1L to allow HTTP/0.9
responses.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
