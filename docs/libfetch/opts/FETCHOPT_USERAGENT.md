---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_USERAGENT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CUSTOMREQUEST (3)
  - FETCHOPT_HTTPHEADER (3)
  - FETCHOPT_REFERER (3)
  - FETCHOPT_REQUEST_TARGET (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

FETCHOPT_USERAGENT - HTTP user-agent header

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_USERAGENT, char *ua);
~~~

# DESCRIPTION

Pass a pointer to a null-terminated string as parameter. It is used to set the
User-Agent: header field in the HTTP request sent to the remote server. You
can also set any custom header with FETCHOPT_HTTPHEADER(3).

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

NULL, no User-Agent: header is used.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    fetch_easy_setopt(fetch, FETCHOPT_USERAGENT, "Dark Secret Ninja/1.0");

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
