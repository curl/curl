---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SOCKS5_GSSAPI_NEC
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY (3)
  - FETCHOPT_PROXY_SERVICE_NAME (3)
Protocol:
  - All
Added-in: 7.19.4
---

# NAME

FETCHOPT_SOCKS5_GSSAPI_NEC - SOCKS proxy GSSAPI negotiation protection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SOCKS5_GSSAPI_NEC, long nec);
~~~

# DESCRIPTION

Pass a long set to 1 to enable or 0 to disable. As part of the GSSAPI
negotiation a protection mode is negotiated. The RFC 1961 says in section
4.3/4.4 it should be protected, but the NEC reference implementation does not.
If enabled, this option allows the unprotected exchange of the protection mode
negotiation.

# DEFAULT

?

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "socks5://proxy");
    fetch_easy_setopt(fetch, FETCHOPT_SOCKS5_GSSAPI_NEC, 1L);
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
