---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAXAGE_CONN
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FORBID_REUSE (3)
  - FETCHOPT_FRESH_CONNECT (3)
  - FETCHOPT_MAXLIFETIME_CONN (3)
  - FETCHOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.65.0
---

# NAME

FETCHOPT_MAXAGE_CONN - max idle time allowed for reusing a connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAXAGE_CONN, long age);
~~~

# DESCRIPTION

Pass a long as parameter containing *age* - the maximum time in seconds
allowed for an existing connection to have been idle to be considered for
reuse for this request.

The "connection cache" holds previously used connections. When a new request
is to be done, libfetch considers any connection that matches for reuse. The
FETCHOPT_MAXAGE_CONN(3) limit prevents libfetch from trying too old
connections for reuse, since old connections have a higher risk of not working
and thus trying them is a performance loss and sometimes service loss due to
the difficulties to figure out the situation. If a connection is found in the
cache that is older than this set *age*, it is closed instead.

# DEFAULT

118 seconds

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* only allow 30 seconds idle time */
    fetch_easy_setopt(fetch, FETCHOPT_MAXAGE_CONN, 30L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
