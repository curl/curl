---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_REDIRECT_URL
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REDIRECT_COUNT (3)
  - FETCHINFO_REDIRECT_TIME_T (3)
  - FETCHOPT_FOLLOWLOCATION (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.18.2
---

# NAME

FETCHINFO_REDIRECT_URL - get the URL a redirect would go to

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_REDIRECT_URL, char **urlp);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the URL a redirect *would* take
you to if you would enable FETCHOPT_FOLLOWLOCATION(3). This can come handy if
you think using the built-in libfetch redirect logic is not good enough for you
but you would still prefer to avoid implementing all the magic of figuring out
the new URL.

This URL is also set if the FETCHOPT_MAXREDIRS(3) limit prevented a redirect to
happen (since 7.54.1).

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
      char *url = NULL;
      fetch_easy_getinfo(fetch, FETCHINFO_REDIRECT_URL, &url);
      if(url)
        printf("Redirect to: %s\n", url);
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
