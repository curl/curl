---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXYUSERNAME
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPAUTH (3)
  - FETCHOPT_PROXYAUTH (3)
  - FETCHOPT_PROXYPASSWORD (3)
  - FETCHOPT_USERNAME (3)
Protocol:
  - All
Added-in: 7.19.1
---

# NAME

FETCHOPT_PROXYUSERNAME - username to use for proxy authentication

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXYUSERNAME,
                          char *username);
~~~

# DESCRIPTION

Pass a char pointer as parameter, which should be pointing to the
null-terminated username to use for the transfer.

FETCHOPT_PROXYUSERNAME(3) sets the username to be used in protocol
authentication with the proxy.

To specify the proxy password use the FETCHOPT_PROXYPASSWORD(3).

The application does not have to keep the string around after setting this
option.

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
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://localhost:8080");
    fetch_easy_setopt(fetch, FETCHOPT_PROXYUSERNAME, "mrsmith");
    fetch_easy_setopt(fetch, FETCHOPT_PROXYPASSWORD, "qwerty");
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
