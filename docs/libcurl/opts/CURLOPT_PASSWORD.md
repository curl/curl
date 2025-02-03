---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PASSWORD
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPAUTH (3)
  - FETCHOPT_PROXYAUTH (3)
  - FETCHOPT_USERNAME (3)
  - FETCHOPT_USERPWD (3)
Protocol:
  - All
Added-in: 7.19.1
---

# NAME

FETCHOPT_PASSWORD - password to use in authentication

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PASSWORD, char *pwd);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be pointing to the
null-terminated password to use for the transfer.

The FETCHOPT_PASSWORD(3) option should be used in conjunction with the
FETCHOPT_USERNAME(3) option.

The application does not have to keep the string around after setting this
option.

Using this option multiple times makes the last set string override the
previous ones. Set it to NULL to disable its use again.

# DEFAULT

blank

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    fetch_easy_setopt(fetch, FETCHOPT_PASSWORD, "qwerty");

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
