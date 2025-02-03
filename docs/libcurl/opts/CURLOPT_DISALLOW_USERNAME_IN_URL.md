---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DISALLOW_USERNAME_IN_URL
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROTOCOLS_STR (3)
  - FETCHOPT_URL (3)
  - fetch_url_set (3)
  - libfetch-security (3)
Protocol:
  - All
Added-in: 7.61.0
---

# NAME

FETCHOPT_DISALLOW_USERNAME_IN_URL - disallow specifying username in the URL

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DISALLOW_USERNAME_IN_URL,
                          long disallow);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to not allow URLs that include a
username.

This is the equivalent to the *FETCHU_DISALLOW_USER* flag for the
fetch_url_set(3) function.

# DEFAULT

0 (disabled)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_DISALLOW_USERNAME_IN_URL, 1L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).

fetch_easy_perform(3) returns FETCHE_LOGIN_DENIED if this option is
enabled and a URL containing a username is specified.
