---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_NOPROGRESS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_PROGRESSFUNCTION (3)
  - FETCHOPT_VERBOSE (3)
  - FETCHOPT_XFERINFOFUNCTION (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_NOPROGRESS - switch off the progress meter

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_NOPROGRESS, long onoff);
~~~

# DESCRIPTION

If *onoff* is to 1, it tells the library to shut off the progress meter
completely for requests done with this *handle*. It also prevents the
FETCHOPT_XFERINFOFUNCTION(3) or FETCHOPT_PROGRESSFUNCTION(3) from
getting called.

# DEFAULT

1, meaning it normally runs without a progress meter.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* enable progress meter */
    fetch_easy_setopt(fetch, FETCHOPT_NOPROGRESS, 0L);

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
