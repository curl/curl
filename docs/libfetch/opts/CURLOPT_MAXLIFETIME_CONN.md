---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAXLIFETIME_CONN
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FORBID_REUSE (3)
  - FETCHOPT_FRESH_CONNECT (3)
  - FETCHOPT_MAXAGE_CONN (3)
  - FETCHOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.80.0
---

# NAME

FETCHOPT_MAXLIFETIME_CONN - max lifetime (since creation) allowed for reusing a connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAXLIFETIME_CONN,
                          long maxlifetime);
~~~

# DESCRIPTION

Pass a long as parameter containing *maxlifetime* - the maximum time in
seconds, since the creation of the connection, that you allow an existing
connection to have to be considered for reuse for this request.

libfetch features a connection cache that holds previously used connections.
When a new request is to be done, libfetch considers any connection that
matches for reuse. The FETCHOPT_MAXLIFETIME_CONN(3) limit prevents
libfetch from trying too old connections for reuse. This can be used for
client-side load balancing. If a connection is found in the cache that is
older than this set *maxlifetime*, it is instead marked for closure.

If set to 0, this behavior is disabled: all connections are eligible for reuse.

# DEFAULT

0 seconds (i.e., disabled)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* only allow each connection to be reused for 30 seconds */
    fetch_easy_setopt(fetch, FETCHOPT_MAXLIFETIME_CONN, 30L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
