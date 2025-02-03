---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_init
Section: 3
Source: libfetch
See-also:
  - fetch_easy_init (3)
  - fetch_global_init (3)
  - fetch_multi_add_handle (3)
  - fetch_multi_cleanup (3)
  - fetch_multi_get_handles (3)
Protocol:
  - All
Added-in: 7.9.6
---

# NAME

fetch_multi_init - create a multi handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHM *fetch_multi_init();
~~~

# DESCRIPTION

This function returns a pointer to a *FETCHM* handle to be used as input to
all the other multi-functions, sometimes referred to as a multi handle in some
places in the documentation. This init call MUST have a corresponding call to
fetch_multi_cleanup(3) when the operation is complete.

By default, several caches are stored in and held by the multi handle: DNS
cache, connection pool, TLS session ID cache and the TLS CA cert cache. All
transfers using the same multi handle share these caches.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  /* init a multi stack */
  FETCHM *multi = fetch_multi_init();
  FETCH *fetch = fetch_easy_init();
  FETCH *fetch2 = fetch_easy_init();

  /* add individual transfers */
  fetch_multi_add_handle(multi, fetch);
  fetch_multi_add_handle(multi, fetch2);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

If this function returns NULL, something went wrong and you cannot use the
other fetch functions.
