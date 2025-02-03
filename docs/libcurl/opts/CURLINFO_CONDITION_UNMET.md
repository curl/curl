---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_CONDITION_UNMET
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TIMECONDITION (3)
  - FETCHOPT_TIMEVALUE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.19.4
---

# NAME

FETCHINFO_CONDITION_UNMET - get info on unmet time conditional or 304 HTTP response.

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_CONDITION_UNMET,
                           long *unmet);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the number 1 if the condition provided in
the previous request did not match (see FETCHOPT_TIMECONDITION(3)). Alas,
if this returns a 1 you know that the reason you did not get data in return is
because it did not fulfill the condition. The long this argument points to
gets a zero stored if the condition instead was met. This can also return 1 if
the server responded with a 304 HTTP status code, for example after sending a
custom "If-Match-*" header.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* January 1, 2020 is 1577833200 */
    fetch_easy_setopt(fetch, FETCHOPT_TIMEVALUE, 1577833200L);

    /* If-Modified-Since the above time stamp */
    fetch_easy_setopt(fetch, FETCHOPT_TIMECONDITION,
                     (long)FETCH_TIMECOND_IFMODSINCE);

    /* Perform the request */
    res = fetch_easy_perform(fetch);

    if(!res) {
      /* check the time condition */
      long unmet;
      res = fetch_easy_getinfo(fetch, FETCHINFO_CONDITION_UNMET, &unmet);
      if(!res) {
        printf("The time condition was %sfulfilled\n", unmet?"NOT":"");
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
