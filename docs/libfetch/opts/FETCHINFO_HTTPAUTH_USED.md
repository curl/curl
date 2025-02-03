---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_HTTPAUTH_USED
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PROXYAUTH_USED (3)
  - FETCHINFO_HTTPAUTH_AVAIL (3)
  - FETCHOPT_HTTPAUTH (3)
Protocol:
  - HTTP
Added-in: 8.12.0
---

# NAME

FETCHINFO_HTTPAUTH_USED - get used HTTP authentication method

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_HTTPAUTH_USED, long *authp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive a bitmask indicating the authentication
method that was used in the previous HTTP request. The meaning of the possible
bits is explained in the FETCHOPT_HTTPAUTH(3) option for fetch_easy_setopt(3).

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
    fetch_easy_setopt(fetch, FETCHOPT_HTTPAUTH, FETCHAUTH_BASIC | FETCHAUTH_DIGEST);
    fetch_easy_setopt(fetch, FETCHOPT_USERNAME, "shrek");
    fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "swamp");

    res = fetch_easy_perform(fetch);

    if(!res) {
      long auth;
      res = fetch_easy_getinfo(fetch, FETCHINFO_HTTPAUTH_USED, &auth);
      if(!res) {
        if(!auth)
          printf("No auth used\n");
        else {
          if(auth == FETCHAUTH_DIGEST)
            printf("Used Digest authentication\n");
          else
            printf("Used Basic authentication\n");
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
