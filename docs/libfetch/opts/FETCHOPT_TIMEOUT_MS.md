---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TIMEOUT_MS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CONNECTTIMEOUT (3)
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_TCP_KEEPALIVE (3)
  - FETCHOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.16.2
---

# NAME

FETCHOPT_TIMEOUT_MS - maximum time the transfer is allowed to complete

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TIMEOUT_MS, long timeout);
~~~

# DESCRIPTION

Pass a long as parameter containing *timeout* - the maximum time in
milliseconds that you allow the libfetch transfer operation to take.

See FETCHOPT_TIMEOUT(3) for details.

# DEFAULT

0 (zero) which means it never times out during transfer.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* complete within 20000 milliseconds */
    fetch_easy_setopt(fetch, FETCHOPT_TIMEOUT_MS, 20000L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
