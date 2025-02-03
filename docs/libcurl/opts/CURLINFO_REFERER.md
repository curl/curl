---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_REFERER
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_REFERER (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_header (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.76.0
---

# NAME

FETCHINFO_REFERER - get the used referrer request header

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_REFERER, char **hdrp);
~~~

# DESCRIPTION

Pass in a pointer to a char pointer and get the referrer header used in the
most recent request.

The **hdrp** pointer is NULL or points to private memory you MUST NOT free -
it gets freed when you call fetch_easy_cleanup(3) on the corresponding fetch
handle.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_REFERER, "https://example.org/referrer");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      char *hdr = NULL;
      fetch_easy_getinfo(fetch, FETCHINFO_REFERER, &hdr);
      if(hdr)
        printf("Referrer header: %s\n", hdr);
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
