---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_RETRY_AFTER
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADERFUNCTION (3)
  - FETCHOPT_STDERR (3)
  - fetch_easy_header (3)
Protocol:
  - All
Added-in: 7.66.0
---

# NAME

FETCHINFO_RETRY_AFTER - returns the Retry-After retry delay

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_RETRY_AFTER,
                           fetch_off_t *retry);
~~~

# DESCRIPTION

Pass a pointer to a fetch_off_t variable to receive the number of seconds the
HTTP server suggests the client should wait until the next request is
issued. The information from the "Retry-After:" header.

While the HTTP header might contain a fixed date string, the
FETCHINFO_RETRY_AFTER(3) always returns the number of seconds to wait -
or zero if there was no header or the header could not be parsed.

This option used to return a negative wait time if the server provided a date
in the past. Since 8.12.0, a negative wait time is returned as zero. In any
case we recommend checking that the wait time is within an acceptable range for
your circumstance.

# DEFAULT

Zero if there was no header.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      fetch_off_t wait = 0;
      fetch_easy_getinfo(fetch, FETCHINFO_RETRY_AFTER, &wait);
      if(wait)
        printf("Wait for %" FETCH_FORMAT_FETCH_OFF_T " seconds\n", wait);
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
