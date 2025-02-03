---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSL_ENABLE_NPN
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSL_ENABLE_ALPN (3)
  - FETCHOPT_SSL_OPTIONS (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.36.0
---

# NAME

FETCHOPT_SSL_ENABLE_NPN - use NPN

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSL_ENABLE_NPN, long npn);
~~~

# DESCRIPTION

Deprecated since 7.86.0. Setting this option has no function.

Pass a long as parameter, 0 or 1 where 1 is for enable and 0 for disable. This
option enables/disables NPN in the SSL handshake (if the SSL backend libfetch
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
    fetch_easy_setopt(fetch, FETCHOPT_SSL_ENABLE_NPN, 1L);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# DEPRECATED

Deprecated since 7.86.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
