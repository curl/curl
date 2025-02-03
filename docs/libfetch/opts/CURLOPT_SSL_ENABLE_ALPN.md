---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSL_ENABLE_ALPN
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSL_ENABLE_NPN (3)
  - FETCHOPT_SSL_OPTIONS (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.36.0
---

# NAME

FETCHOPT_SSL_ENABLE_ALPN - Application Layer Protocol Negotiation

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSL_ENABLE_ALPN, long npn);
~~~

# DESCRIPTION

Pass a long as parameter, 0 or 1 where 1 is for enable and 0 for disable. This
option enables/disables ALPN in the SSL handshake (if the SSL backend libfetch
is built to use supports it), which can be used to negotiate http2.

# DEFAULT

1, enabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_SSL_ENABLE_ALPN, 0L);
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
