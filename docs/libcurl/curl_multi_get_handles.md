---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_get_handles
Section: 3
Source: libfetch
See-also:
  - fetch_multi_add_handle (3)
  - fetch_multi_cleanup (3)
  - fetch_multi_init (3)
  - fetch_multi_remove_handle (3)
Protocol:
  - All
Added-in: 8.4.0
---

# NAME

fetch_multi_get_handles - return all added easy handles

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCH **fetch_multi_get_handles(FETCHM *multi_handle);
~~~

# DESCRIPTION

Returns an array with pointers to all added easy handles. The end of the list
is marked with a NULL pointer.

Even if there is not a single easy handle added, this still returns an array
but with only a single NULL pointer entry.

The returned array contains all the handles that are present at the time of
the call. As soon as a handle has been removed from or a handle has been added
to the multi handle after the handle array was returned, the two data points
are out of sync.

The order of the easy handles within the array is not guaranteed.

The returned array must be freed with a call to fetch_free(3) after use.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  /* init a multi stack */
  FETCHM *multi = fetch_multi_init();
  FETCH *fetch = fetch_easy_init();

  if(fetch) {
    /* add the transfer */
    fetch_multi_add_handle(multi, fetch);

    /* extract all added handles */
    FETCH **list = fetch_multi_get_handles(multi);

    if(list) {
      int i;
      /* remove all added handles */
      for(i = 0; list[i]; i++) {
        fetch_multi_remove_handle(multi, list[i]);
      }
      fetch_free(list);
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns NULL on failure. Otherwise it returns a pointer to an allocated array.
