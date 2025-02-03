---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TIMEOUT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CONNECTTIMEOUT (3)
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_TCP_KEEPALIVE (3)
  - FETCHOPT_TIMEOUT_MS (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_TIMEOUT - maximum time the transfer is allowed to complete

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TIMEOUT, long timeout);
~~~

# DESCRIPTION

Pass a long as parameter containing *timeout* - the maximum time in
seconds that you allow the entire transfer operation to take. The whole thing,
from start to end. Normally, name lookups can take a considerable time and
limiting operations risk aborting perfectly normal operations.

FETCHOPT_TIMEOUT_MS(3) is the same function but set in milliseconds.

If both FETCHOPT_TIMEOUT(3) and FETCHOPT_TIMEOUT_MS(3) are set, the
value set last is used.

Since this option puts a hard limit on how long time a request is allowed to
take, it has limited use in dynamic use cases with varying transfer
times. That is especially apparent when using the multi interface, which may
queue the transfer, and that time is included. You are advised to explore
FETCHOPT_LOW_SPEED_LIMIT(3), FETCHOPT_LOW_SPEED_TIME(3) or using
FETCHOPT_PROGRESSFUNCTION(3) to implement your own timeout logic.

The connection timeout set with FETCHOPT_CONNECTTIMEOUT(3) is included in
this general all-covering timeout.

With FETCHOPT_CONNECTTIMEOUT(3) set to 3 and FETCHOPT_TIMEOUT(3) set
to 5, the operation can never last longer than 5 seconds.

With FETCHOPT_CONNECTTIMEOUT(3) set to 4 and FETCHOPT_TIMEOUT(3) set
to 2, the operation can never last longer than 2 seconds.

This option may cause libfetch to use the SIGALRM signal to timeout system
calls on builds not using asynch DNS. In Unix-like systems, this might cause
signals to be used unless FETCHOPT_NOSIGNAL(3) is set.

# DEFAULT

0 (zero) which means it never times out during transfer.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* complete within 20 seconds */
    fetch_easy_setopt(fetch, FETCHOPT_TIMEOUT, 20L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
