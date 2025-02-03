---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TIMECONDITION
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_FILETIME (3)
  - FETCHOPT_TIMEVALUE (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

FETCHOPT_TIMECONDITION - select condition for a time request

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TIMECONDITION, long cond);
~~~

# DESCRIPTION

Pass a long as parameter. This defines how the FETCHOPT_TIMEVALUE(3) time
value is treated. You can set this parameter to *FETCH_TIMECOND_IFMODSINCE*
or *FETCH_TIMECOND_IFUNMODSINCE*.

The last modification time of a file is not always known and in such instances
this feature has no effect even if the given time condition would not have
been met. fetch_easy_getinfo(3) with the *FETCHINFO_CONDITION_UNMET*
option can be used after a transfer to learn if a zero-byte successful
"transfer" was due to this condition not matching.

# DEFAULT

FETCH_TIMECOND_NONE (0)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* January 1, 2020 is 1577833200 */
    fetch_easy_setopt(fetch, FETCHOPT_TIMEVALUE, 1577833200L);

    /* If-Modified-Since the above time stamp */
    fetch_easy_setopt(fetch, FETCHOPT_TIMECONDITION,
                     (long)FETCH_TIMECOND_IFMODSINCE);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
