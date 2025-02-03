---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_PROXYAUTH_USED
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_HTTPAUTH_USED (3)
  - FETCHINFO_PROXYAUTH_AVAIL (3)
  - FETCHOPT_HTTPAUTH (3)
Protocol:
  - HTTP
Added-in: 8.12.0
---

# NAME

FETCHINFO_PROXYAUTH_USED - get used HTTP proxy authentication method

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_PROXYAUTH_USED, long *authp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive a bitmask indicating the authentication
method that was used in the previous request done over an HTTP proxy. The
meaning of the possible bits is explained in the FETCHOPT_HTTPAUTH(3) option
for fetch_easy_setopt(3).

The returned value has zero or one bit set.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://proxy.example.com");
    fetch_easy_setopt(fetch, FETCHOPT_PROXYAUTH,
                     FETCHAUTH_BASIC | FETCHAUTH_DIGEST);
    fetch_easy_setopt(fetch, FETCHOPT_PROXYUSERNAME, "shrek");
    fetch_easy_setopt(fetch, FETCHOPT_PROXYPASSWORD, "swamp");

    res = fetch_easy_perform(fetch);

    if(!res) {
      long auth;
      res = fetch_easy_getinfo(fetch, FETCHINFO_PROXYAUTH_USED, &auth);
      if(!res) {
        if(!auth)
          printf("No auth used\n");
        else {
          if(auth == FETCHAUTH_DIGEST)
            printf("Used Digest proxy authentication\n");
          else
            printf("Used Basic proxy authentication\n");
        }
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
