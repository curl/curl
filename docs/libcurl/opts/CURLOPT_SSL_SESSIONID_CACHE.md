---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSL_SESSIONID_CACHE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DNS_CACHE_TIMEOUT (3)
  - FETCHOPT_MAXAGE_CONN (3)
  - FETCHOPT_MAXLIFETIME_CONN (3)
  - FETCHOPT_SSLVERSION (3)
Protocol:
  - TLS
TLS-backend:
  - All
Added-in: 7.16.0
---

# NAME

FETCHOPT_SSL_SESSIONID_CACHE - use the SSL session-ID cache

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSL_SESSIONID_CACHE,
                         long enabled);
~~~

# DESCRIPTION

Pass a long set to 0 to disable libfetch's use of SSL session-ID caching. Set
this to 1 to enable it. By default all transfers are done using the cache
enabled. While nothing ever should get hurt by attempting to reuse SSL
session-IDs, there seem to be or have been broken SSL implementations in the
wild that may require you to disable this in order for you to succeed.

# DEFAULT

1

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* switch off session-id use */
    fetch_easy_setopt(fetch, FETCHOPT_SSL_SESSIONID_CACHE, 0L);
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
