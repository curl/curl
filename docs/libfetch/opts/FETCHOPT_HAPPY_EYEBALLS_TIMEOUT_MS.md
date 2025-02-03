---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS
Section: 3
Source: libfetch
Protocol:
  - All
See-also:
  - FETCHOPT_CONNECTTIMEOUT_MS (3)
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_TIMEOUT (3)
Added-in: 7.59.0
---

# NAME

FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS - head start for IPv6 for happy eyeballs

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
                          long timeout);
~~~

# DESCRIPTION

Happy eyeballs is an algorithm that attempts to connect to both IPv4 and IPv6
addresses for dual-stack hosts, preferring IPv6 first for *timeout*
milliseconds. If the IPv6 address cannot be connected to within that time then
a connection attempt is made to the IPv4 address in parallel. The first
connection to be established is the one that is used.

The range of suggested useful values for *timeout* is limited. Happy
Eyeballs RFC 6555 says "It is RECOMMENDED that connection attempts be paced
150-250 ms apart to balance human factors against network load." libfetch
currently defaults to 200 ms. Firefox and Chrome currently default to 300 ms.

# DEFAULT

FETCH_HET_DEFAULT (currently defined as 200L)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_HAPPY_EYEBALLS_TIMEOUT_MS, 300L);

    fetch_easy_perform(fetch);

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
