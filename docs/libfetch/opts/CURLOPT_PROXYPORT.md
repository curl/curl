---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXYPORT
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PRIMARY_PORT (3)
  - FETCHOPT_PORT (3)
  - FETCHOPT_PROXY (3)
  - FETCHOPT_PROXYTYPE (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_PROXYPORT - port number the proxy listens on

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXYPORT, long port);
~~~

# DESCRIPTION

We discourage use of this option.

Pass a long with this option to set the proxy port to connect to unless it is
specified in the proxy string FETCHOPT_PROXY(3) or uses 443 for https proxies
and 1080 for all others as default.

Disabling this option, setting it to zero, makes it not specified which makes
libfetch use the default proxy port number or the port number specified in the
proxy URL string.

While this accepts a 'long', the port number is 16 bit so it cannot be larger
than 65535.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "localhost");
    fetch_easy_setopt(fetch, FETCHOPT_PROXYPORT, 8080L);
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
