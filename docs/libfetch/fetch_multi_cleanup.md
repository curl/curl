---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_cleanup
Section: 3
Source: libfetch
See-also:
  - fetch_easy_cleanup (3)
  - fetch_easy_init (3)
  - fetch_multi_get_handles (3)
  - fetch_multi_init (3)
Protocol:
  - All
Added-in: 7.9.6
---

# NAME

fetch_multi_cleanup - close down a multi session

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_cleanup(FETCHM *multi_handle);
~~~

# DESCRIPTION

This function is the opposite of fetch_multi_init(3). Cleans up and removes a
whole multi stack. It does not free or touch any individual easy handles in
any way - they still need to be closed individually, using the usual
fetch_easy_cleanup(3) way. The order of cleaning up should be:

1 - fetch_multi_remove_handle(3) before any easy handles are cleaned up

2 - fetch_easy_cleanup(3) can now be called independently since the easy
handle is no longer connected to the multi handle

3 - fetch_multi_cleanup(3) should be called when all easy handles are
removed

When this function is called, remaining entries in the connection pool held by
the multi handle are shut down, which might trigger calls to the
FETCHMOPT_SOCKETFUNCTION(3) callback.

Passing in a NULL pointer in *multi_handle* makes this function return
FETCHM_BAD_HANDLE immediately with no other action.

Any use of the **multi_handle** after this function has been called and have
returned, is illegal.
# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHM *multi = fetch_multi_init();

  /* when the multi transfer is done ... */

  /* remove all easy handles, then: */
  fetch_multi_cleanup(multi);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
