---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_upkeep
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TCP_KEEPALIVE (3)
  - FETCHOPT_TCP_KEEPIDLE (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

fetch_easy_upkeep - keep existing connections alive

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_upkeep(FETCH *handle);
~~~

# DESCRIPTION

Some protocols have "connection upkeep" mechanisms. These mechanisms usually
send some traffic on existing connections in order to keep them alive; this
can prevent connections from being closed due to overzealous firewalls, for
example.

Currently the only protocol with a connection upkeep mechanism is HTTP/2: when
the connection upkeep interval is exceeded and fetch_easy_upkeep(3)
is called, an HTTP/2 PING frame is sent on the connection.

This function must be explicitly called in order to perform the upkeep work.
The connection upkeep interval is set with
FETCHOPT_UPKEEP_INTERVAL_MS(3).

If you call this function on an easy handle that uses a shared connection cache
then upkeep is performed on the connections in that cache, even if those
connections were never used by the easy handle. (Added in 8.10.0)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    /* Make a connection to an HTTP/2 server. */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* Set the interval to 30000ms / 30s */
    fetch_easy_setopt(fetch, FETCHOPT_UPKEEP_INTERVAL_MS, 30000L);

    fetch_easy_perform(fetch);

    /* Perform more work here. */

    /* While the connection is being held open, fetch_easy_upkeep() can be
       called. If fetch_easy_upkeep() is called and the time since the last
       upkeep exceeds the interval, then an HTTP/2 PING is sent. */
    fetch_easy_upkeep(fetch);

    /* Perform more work here. */

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.
