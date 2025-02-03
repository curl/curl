---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAXCONNECTS
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_MAXCONNECTS (3)
  - FETCHMOPT_MAX_HOST_CONNECTIONS (3)
  - FETCHMOPT_MAX_TOTAL_CONNECTIONS (3)
  - FETCHOPT_MAXREDIRS (3)
Protocol:
  - All
Added-in: 7.7
---

# NAME

FETCHOPT_MAXCONNECTS - maximum connection cache size

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAXCONNECTS, long amount);
~~~

# DESCRIPTION

Pass a long. The set *amount* is the maximum number of connections that
libfetch may keep alive in its connection cache after use. The default is 5,
and there is not much point in changing this value unless you are perfectly
aware of how this works. This concerns connections using any of the protocols
that support persistent connections.

When reaching the maximum limit, fetch closes the oldest connection present in
the cache to prevent the number of connections from increasing.

If you already have performed transfers with this fetch handle, setting a
smaller FETCHOPT_MAXCONNECTS(3) than before may cause open connections to get
closed unnecessarily.

If you add this easy handle to a multi handle, this setting is not
acknowledged, and you must instead use fetch_multi_setopt(3) and the
FETCHMOPT_MAXCONNECTS(3) option.

# DEFAULT

5

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* limit the connection cache for this handle to no more than 3 */
    fetch_easy_setopt(fetch, FETCHOPT_MAXCONNECTS, 3L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
