---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_TCP_KEEPALIVE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_MAX_RECV_SPEED_LARGE (3)
  - FETCHOPT_TCP_KEEPIDLE (3)
  - FETCHOPT_TCP_KEEPINTVL (3)
  - FETCHOPT_TCP_KEEPCNT (3)
Protocol:
  - TCP
Added-in: 7.25.0
---

# NAME

FETCHOPT_TCP_KEEPALIVE - TCP keep-alive probing

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_TCP_KEEPALIVE, long probe);
~~~

# DESCRIPTION

Pass a long. If set to 1, TCP keepalive probes are used. The delay and
frequency of these probes can be controlled by the
FETCHOPT_TCP_KEEPIDLE(3), FETCHOPT_TCP_KEEPINTVL(3), and FETCHOPT_TCP_KEEPCNT(3)
options, provided the operating system supports them. Set to 0 (default behavior)
to disable keepalive probes.

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

    /* enable TCP keep-alive for this transfer */
    fetch_easy_setopt(fetch, FETCHOPT_TCP_KEEPALIVE, 1L);

    /* keep-alive idle time to 120 seconds */
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
