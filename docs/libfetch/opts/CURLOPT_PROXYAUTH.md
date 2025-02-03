---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXYAUTH
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPAUTH (3)
  - FETCHOPT_PROXY (3)
  - FETCHOPT_PROXYPORT (3)
  - FETCHOPT_PROXYTYPE (3)
  - FETCHOPT_PROXYUSERPWD (3)
Protocol:
  - All
Added-in: 7.10.7
---

# NAME

FETCHOPT_PROXYAUTH - HTTP proxy authentication methods

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXYAUTH, long bitmask);
~~~

# DESCRIPTION

Pass a long as parameter, which is set to a bitmask, to tell libfetch which
HTTP authentication method(s) you want it to use for your proxy
authentication. If more than one bit is set, libfetch first queries the site to
see what authentication methods it supports and then it picks the best one you
allow it to use. For some methods, this induces an extra network round-trip.
Set the actual name and password with the FETCHOPT_PROXYUSERPWD(3)
option.

The bitmask can be constructed by the bits listed and described in the
FETCHOPT_HTTPAUTH(3) man page.

# DEFAULT

FETCHAUTH_BASIC

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* use this proxy */
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://local.example.com:1080");
    /* allow whatever auth the proxy speaks */
    fetch_easy_setopt(fetch, FETCHOPT_PROXYAUTH, FETCHAUTH_ANY);
    /* set the proxy credentials */
    fetch_easy_setopt(fetch, FETCHOPT_PROXYUSERPWD, "james:007");
    ret = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
