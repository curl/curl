---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SOCKS5_AUTH
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY (3)
  - FETCHOPT_PROXYTYPE (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

FETCHOPT_SOCKS5_AUTH - methods for SOCKS5 proxy authentication

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SOCKS5_AUTH, long bitmask);
~~~

# DESCRIPTION

Pass a long as parameter, which is set to a bitmask, to tell libfetch which
authentication method(s) are allowed for SOCKS5 proxy authentication. The only
supported flags are *FETCHAUTH_BASIC*, which allows username/password
authentication, *FETCHAUTH_GSSAPI*, which allows GSS-API authentication, and
*FETCHAUTH_NONE*, which allows no authentication. Set the actual username and
password with the FETCHOPT_PROXYUSERPWD(3) option.

# DEFAULT

FETCHAUTH_BASIC|FETCHAUTH_GSSAPI

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* request to use a SOCKS5 proxy */
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "socks5://user:pass@myproxy.com");

    /* enable username/password authentication only */
    fetch_easy_setopt(fetch, FETCHOPT_SOCKS5_AUTH, (long)FETCHAUTH_BASIC);

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
