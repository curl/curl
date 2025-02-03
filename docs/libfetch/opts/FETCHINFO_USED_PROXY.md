---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_USED_PROXY
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_NOPROXY (3)
  - FETCHOPT_PROXY (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 8.7.0
---

# NAME

FETCHINFO_USED_PROXY - whether the transfer used a proxy

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_USED_PROXY,
                           long *authp);
~~~

# DESCRIPTION

Pass a pointer to a long. It gets set to zero set if no proxy was used in the
previous transfer or a non-zero value if a proxy was used.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(int argc, char *argv[])
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, argv[1]);
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://127.0.0.1:80");
    fetch_easy_setopt(fetch, FETCHOPT_NOPROXY, "example.com");

    res = fetch_easy_perform(fetch);

    if(!res) {
      /* extract the available proxy authentication types */
      long used;
      res = fetch_easy_getinfo(fetch, FETCHINFO_USED_PROXY, &used);
      if(!res) {
        printf("The proxy was %sused\n", used ? "": "NOT ");
      }
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
