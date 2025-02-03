---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FORBID_REUSE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FRESH_CONNECT (3)
  - FETCHOPT_MAXCONNECTS (3)
  - FETCHOPT_MAXLIFETIME_CONN (3)
Protocol:
  - All
Added-in: 7.7
---

# NAME

FETCHOPT_FORBID_REUSE - make connection get closed at once after use

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FORBID_REUSE, long close);
~~~

# DESCRIPTION

Pass a long. Set *close* to 1 to make libfetch explicitly close the
connection when done with the transfer. Normally, libfetch keeps all
connections alive when done with one transfer in case a succeeding one follows
that can reuse them. This option should be used with caution and only if you
understand what it does as it can seriously impact performance.

Set to 0 to have libfetch keep the connection open for possible later reuse
(default behavior).

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_FORBID_REUSE, 1L);
    fetch_easy_perform(fetch);

    /* this second transfer may not reuse the same connection */
    fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
