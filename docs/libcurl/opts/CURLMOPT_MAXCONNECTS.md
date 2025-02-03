---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_MAXCONNECTS
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_MAX_HOST_CONNECTIONS (3)
  - FETCHOPT_MAXCONNECTS (3)
Protocol:
  - All
Added-in: 7.16.3
---

# NAME

FETCHMOPT_MAXCONNECTS - size of connection cache

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_MAXCONNECTS, long max);
~~~

# DESCRIPTION

Pass a long indicating the **max**, the maximum amount of connections that
libfetch may keep alive in its connection cache after use. By default libfetch
enlarges the size for each added easy handle to make it fit 4 times the number
of added easy handles.

By setting this option, you prevent the cache size from growing beyond the
limit set by you.

When the cache is full, fetch closes the oldest connection present in the cache
to prevent the number of connections from increasing.

This option is for the multi handle's use only, when using the easy interface
you should instead use the FETCHOPT_MAXCONNECTS(3) option.

See FETCHMOPT_MAX_TOTAL_CONNECTIONS(3) for limiting the number of active
connections.

Changing this value when there are transfers in progress is possible, and the
new value is then used the next time checks are performed. Lowering the value
does not close down any active transfers, it simply does not allow new ones to
get made.

# DEFAULT

See DESCRIPTION

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHM *m = fetch_multi_init();
  /* only keep 10 connections in the cache */
  fetch_multi_setopt(m, FETCHMOPT_MAXCONNECTS, 10L);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_multi_setopt(3) returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
