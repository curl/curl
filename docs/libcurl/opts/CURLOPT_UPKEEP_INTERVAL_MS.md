---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_UPKEEP_INTERVAL_MS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TCP_KEEPALIVE (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

FETCHOPT_UPKEEP_INTERVAL_MS - connection upkeep interval

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_UPKEEP_INTERVAL_MS,
                          long upkeep_interval_ms);
~~~

# DESCRIPTION

Some protocols have "connection upkeep" mechanisms. These mechanisms usually
send some traffic on existing connections in order to keep them alive; this
can prevent connections from being closed due to overzealous firewalls, for
example.

The user needs to explicitly call fetch_easy_upkeep(3) in order to
perform the upkeep work.

Currently the only protocol with a connection upkeep mechanism is HTTP/2: when
the connection upkeep interval is exceeded and fetch_easy_upkeep(3)
is called, an HTTP/2 PING frame is sent on the connection.

# DEFAULT

FETCH_UPKEEP_INTERVAL_DEFAULT (currently defined as 60000L, which is 60 seconds)

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

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
