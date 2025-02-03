---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_REQUEST_TARGET
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CUSTOMREQUEST (3)
  - FETCHOPT_HTTPGET (3)
  - FETCHOPT_PATH_AS_IS (3)
  - FETCHOPT_URL (3)
Protocol:
  - HTTP
Added-in: 7.55.0
---

# NAME

FETCHOPT_REQUEST_TARGET - alternative target for this request

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_REQUEST_TARGET, string);
~~~

# DESCRIPTION

Pass a char pointer to string which libfetch uses in the upcoming request
instead of the path as extracted from the URL.

libfetch passes on the verbatim string in its request without any filter or
other safe guards. That includes white space and control characters.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

The application does not have to keep the string around after setting this
option.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/*");
    fetch_easy_setopt(fetch, FETCHOPT_CUSTOMREQUEST, "OPTIONS");

    /* issue an OPTIONS * request (no leading slash) */
    fetch_easy_setopt(fetch, FETCHOPT_REQUEST_TARGET, "*");

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
