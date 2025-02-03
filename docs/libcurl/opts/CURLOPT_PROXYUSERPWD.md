---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXYUSERPWD
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY (3)
  - FETCHOPT_PROXYPASSWORD (3)
  - FETCHOPT_PROXYTYPE (3)
  - FETCHOPT_PROXYUSERNAME (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_PROXYUSERPWD - username and password to use for proxy authentication

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXYUSERPWD, char *userpwd);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be [username]:[password] to use
for the connection to the HTTP proxy. Both the name and the password are URL
decoded before used, so to include for example a colon in the username you
should encode it as %3A. (This is different to how FETCHOPT_USERPWD(3) is
used - beware.)

Use FETCHOPT_PROXYAUTH(3) to specify the authentication method.

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
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://localhost:8080");
    fetch_easy_setopt(fetch, FETCHOPT_PROXYUSERPWD, "clark%20kent:superman");
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
