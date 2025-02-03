---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_COOKIEJAR
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_COOKIE (3)
  - FETCHOPT_COOKIEFILE (3)
  - FETCHOPT_COOKIELIST (3)
Protocol:
  - HTTP
Added-in: 7.9
---

# NAME

FETCHOPT_COOKIEJAR - filename to store cookies to

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_COOKIEJAR, char *filename);
~~~

# DESCRIPTION

Pass a *filename* as a char *, null-terminated. This makes libfetch write all
internally known cookies to the specified file when fetch_easy_cleanup(3) is
called. If no cookies are kept in memory at that time, no file is created.
Specify "-" as filename to instead have the cookies written to stdout. Using
this option also enables cookies for this session, so if you for example
follow a redirect it makes matching cookies get sent accordingly.

Note that libfetch does not read any cookies from the cookie jar specified with
this option. To read cookies from a file, use FETCHOPT_COOKIEFILE(3).

If the cookie jar file cannot be created or written to (when the
fetch_easy_cleanup(3) is called), libfetch does not and cannot report an error
for this. Using FETCHOPT_VERBOSE(3) or FETCHOPT_DEBUGFUNCTION(3) displays a
warning, but that is the only visible feedback you get about this possibly
lethal situation.

Cookies are imported in the Set-Cookie format without a domain name are not
exported by this option.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# SECURITY CONCERNS

libfetch cannot fully protect against attacks where an attacker has write
access to the same directory where it is directed to save files. This is
particularly sensitive if you save files using elevated privileges.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* export cookies to this file when closing the handle */
    fetch_easy_setopt(fetch, FETCHOPT_COOKIEJAR, "/tmp/cookies.txt");

    res = fetch_easy_perform(fetch);

    /* close the handle, write the cookies */
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
