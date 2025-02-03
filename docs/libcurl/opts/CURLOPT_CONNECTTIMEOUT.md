---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CONNECTTIMEOUT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_MAX_RECV_SPEED_LARGE (3)
  - FETCHOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.7
---

# NAME

FETCHOPT_CONNECTTIMEOUT - timeout for the connect phase

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CONNECTTIMEOUT, long timeout);
~~~

# DESCRIPTION

Pass a long. It sets the maximum time in seconds that you allow the connection
phase to take. This timeout only limits the connection phase, it has no impact
once libfetch has connected. The connection phase includes the name resolve
(DNS) and all protocol handshakes and negotiations until there is an
established connection with the remote side.

Set this option to zero to switch to the default built-in connection timeout -
300 seconds. See also the FETCHOPT_TIMEOUT(3) option.

FETCHOPT_CONNECTTIMEOUT_MS(3) is the same function but set in milliseconds.

If both FETCHOPT_CONNECTTIMEOUT(3) and FETCHOPT_CONNECTTIMEOUT_MS(3)
are set, the value set last is used.

The connection timeout is included in the general all-covering
FETCHOPT_TIMEOUT(3):

With FETCHOPT_CONNECTTIMEOUT(3) set to 3 and FETCHOPT_TIMEOUT(3) set
to 5, the operation can never last longer than 5 seconds, and the connection
phase cannot last longer than 3 seconds.

With FETCHOPT_CONNECTTIMEOUT(3) set to 4 and FETCHOPT_TIMEOUT(3) set
to 2, the operation can never last longer than 2 seconds. Including the
connection phase.

This option may cause libfetch to use the SIGALRM signal to timeout system
calls on builds not using asynch DNS. In Unix-like systems, this might cause
signals to be used unless FETCHOPT_NOSIGNAL(3) is set.

# DEFAULT

300

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* complete connection within 10 seconds */
    fetch_easy_setopt(fetch, FETCHOPT_CONNECTTIMEOUT, 10L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
