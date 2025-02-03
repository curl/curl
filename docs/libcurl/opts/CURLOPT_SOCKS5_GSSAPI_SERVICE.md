---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SOCKS5_GSSAPI_SERVICE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PROXY (3)
  - FETCHOPT_PROXYTYPE (3)
Protocol:
  - All
Added-in: 7.19.4
---

# NAME

FETCHOPT_SOCKS5_GSSAPI_SERVICE - SOCKS5 proxy authentication service name

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SOCKS5_GSSAPI_SERVICE,
                          char *name);
~~~

# DESCRIPTION

Deprecated since 7.49.0. Use FETCHOPT_PROXY_SERVICE_NAME(3) instead.

Pass a char pointer as parameter to a string holding the *name* of the
service. The default service name for a SOCKS5 server is *rcmd*. This option
allows you to change it.

The application does not have to keep the string around after setting this
option.

# DEFAULT

See above

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
    fetch_easy_setopt(fetch, FETCHOPT_SOCKS5_GSSAPI_SERVICE, "rcmd-special");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# DEPRECATED

Deprecated since 7.49.0

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
