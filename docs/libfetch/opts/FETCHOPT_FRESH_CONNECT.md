---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FRESH_CONNECT
Section: 3
Source: libfetch
Protocol:
  - All
See-also:
  - FETCHOPT_FORBID_REUSE (3)
  - FETCHOPT_MAXAGE_CONN (3)
  - FETCHOPT_MAXLIFETIME_CONN (3)
Added-in: 7.7
---

# NAME

FETCHOPT_FRESH_CONNECT - force a new connection to be used

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FRESH_CONNECT, long fresh);
~~~

# DESCRIPTION

Pass a long. Set to 1 to make the next transfer use a new (fresh) connection
by force instead of trying to reuse an existing one. This option should be
used with caution and only if you understand what it does as it may impact
performance negatively.

Related functionality is FETCHOPT_FORBID_REUSE(3) which makes sure the
connection is closed after use so that it cannot be reused.

Set *fresh* to 0 to have libfetch attempt reusing an existing connection
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
    fetch_easy_setopt(fetch, FETCHOPT_FRESH_CONNECT, 1L);
    /* this transfer must use a new connection, not reuse an existing */
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
