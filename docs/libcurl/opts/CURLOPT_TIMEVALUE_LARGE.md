---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TIMEVALUE_LARGE
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_FILETIME (3)
  - FETCHOPT_TIMECONDITION (3)
  - FETCHOPT_TIMEVALUE (3)
Protocol:
  - HTTP
Added-in: 7.59.0
---

# NAME

FETCHOPT_TIMEVALUE_LARGE - time value for conditional

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TIMEVALUE_LARGE,
                          fetch_off_t val);
~~~

# DESCRIPTION

Pass a fetch_off_t *val* as parameter. This should be the time counted as
seconds since 1 Jan 1970, and the time is used in a condition as specified
with FETCHOPT_TIMECONDITION(3).

The difference between this option and FETCHOPT_TIMEVALUE(3) is the type of the
argument. On systems where 'long' is only 32 bits wide, this option has to be
used to set dates beyond the year 2038.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* January 1, 2020 is 1577833200 */
    fetch_easy_setopt(fetch, FETCHOPT_TIMEVALUE_LARGE, (fetch_off_t)1577833200);

    /* If-Modified-Since the above time stamp */
    fetch_easy_setopt(fetch, FETCHOPT_TIMECONDITION, FETCH_TIMECOND_IFMODSINCE);

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
