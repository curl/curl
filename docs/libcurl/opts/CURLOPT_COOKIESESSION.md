---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_COOKIESESSION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_COOKIE (3)
  - FETCHOPT_COOKIEFILE (3)
  - FETCHOPT_COOKIEJAR (3)
Protocol:
  - HTTP
Added-in: 7.9.7
---

# NAME

FETCHOPT_COOKIESESSION - start a new cookie session

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_COOKIESESSION, long init);
~~~

# DESCRIPTION

Pass a long set to 1 to mark this as a new cookie "session". It forces libfetch
to ignore all cookies it is about to load that are "session cookies" from the
previous session. By default, libfetch always loads all cookies, independent if
they are session cookies or not. Session cookies are cookies without expiry
date and they are meant to be alive and existing for this "session" only.

A "session" is usually defined in browser land for as long as you have your
browser up, more or less. libfetch needs the application to use this option to
tell it when a new session starts, otherwise it assumes everything is still in
the same session.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* new "session", do not load session cookies */
    fetch_easy_setopt(fetch, FETCHOPT_COOKIESESSION, 1L);

    /* get the (non session) cookies from this file */
    fetch_easy_setopt(fetch, FETCHOPT_COOKIEFILE, "/tmp/cookies.txt");

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
