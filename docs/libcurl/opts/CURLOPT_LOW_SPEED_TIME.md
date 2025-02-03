---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_LOW_SPEED_TIME
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_LOW_SPEED_TIME - low speed limit time period

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_LOW_SPEED_TIME,
                          long speedtime);
~~~

# DESCRIPTION

Pass a long as parameter. It contains the time in number seconds that the
transfer speed should be below the FETCHOPT_LOW_SPEED_LIMIT(3) for the
library to consider it too slow and abort.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    /* abort if slower than 30 bytes/sec during 60 seconds */
    fetch_easy_setopt(fetch, FETCHOPT_LOW_SPEED_TIME, 60L);
    fetch_easy_setopt(fetch, FETCHOPT_LOW_SPEED_LIMIT, 30L);
    res = fetch_easy_perform(fetch);
    if(FETCHE_OPERATION_TIMEDOUT == res) {
      printf("Timeout.\n");
    }
    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
