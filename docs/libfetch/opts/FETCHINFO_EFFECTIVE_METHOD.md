---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_EFFECTIVE_METHOD
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CUSTOMREQUEST (3)
  - FETCHOPT_FOLLOWLOCATION (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.72.0
---

# NAME

FETCHINFO_EFFECTIVE_METHOD - get the last used HTTP method

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_EFFECTIVE_METHOD,
                           char **methodp);
~~~

# DESCRIPTION

Pass in a pointer to a char pointer and get the last used effective HTTP
method.

In cases when you have asked libfetch to follow redirects, the method may not be
the same method the first request would use.

The **methodp** pointer is NULL or points to private memory. You MUST NOT
free - it gets freed when you call fetch_easy_cleanup(3) on the
corresponding fetch handle.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, "data");
    fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      char *method = NULL;
      fetch_easy_getinfo(fetch, FETCHINFO_EFFECTIVE_METHOD, &method);
      if(method)
        printf("Redirected to method: %s\n", method);
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
