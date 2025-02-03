---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_REFERER
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REDIRECT_URL (3)
  - FETCHINFO_REFERER (3)
  - FETCHOPT_HTTPHEADER (3)
  - FETCHOPT_USERAGENT (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

FETCHOPT_REFERER - the HTTP referer header

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_REFERER, char *where);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used to set the
Referer: header field in the HTTP request sent to the remote server. You can
set any custom header with FETCHOPT_HTTPHEADER(3).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* tell it where we found the link to this place */
    fetch_easy_setopt(fetch, FETCHOPT_REFERER, "https://example.org/me.html");

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
