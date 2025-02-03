---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TCP_KEEPINTVL
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_TCP_KEEPALIVE (3)
  - FETCHOPT_TCP_KEEPIDLE (3)
  - FETCHOPT_TCP_KEEPCNT (3)
Protocol:
  - TCP
Added-in: 7.25.0
---

# NAME

FETCHOPT_TCP_KEEPINTVL - TCP keep-alive interval

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TCP_KEEPINTVL, long interval);
~~~

# DESCRIPTION

Pass a long. Sets the interval, in seconds, to wait between sending keepalive
probes. Not all operating systems support this option. (Added in 7.25.0)

The maximum value this accepts is 2147483648. Any larger value is capped to
this amount.

# DEFAULT

60

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* enable TCP keep-alive for this transfer */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPALIVE, 1L);

    /* set keep-alive idle time to 120 seconds */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPIDLE, 120L);

    /* interval time between keep-alive probes: 60 seconds */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPINTVL, 60L);

    /* maximum number of keep-alive probes: 3 */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPCNT, 3L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
