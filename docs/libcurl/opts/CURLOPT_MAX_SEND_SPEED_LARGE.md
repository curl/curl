---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAX_SEND_SPEED_LARGE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_LOW_SPEED_LIMIT (3)
  - FETCHOPT_MAX_RECV_SPEED_LARGE (3)
Protocol:
  - All
Added-in: 7.15.5
---

# NAME

FETCHOPT_MAX_SEND_SPEED_LARGE - rate limit data upload speed

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAX_SEND_SPEED_LARGE,
                          fetch_off_t maxspeed);
~~~

# DESCRIPTION

Pass a fetch_off_t as parameter with the *maxspeed*. If an upload exceeds
this speed (counted in bytes per second) the transfer pauses to keep the
average speed less than or equal to the parameter value. Defaults to unlimited
speed.

This is not an exact science. libfetch attempts to keep the average speed below
the given threshold over a period time.

If you set *maxspeed* to a value lower than
FETCHOPT_UPLOAD_BUFFERSIZE(3), libfetch might "shoot over" the limit on
its first send and still send off a full buffer.

This option does not affect transfer speeds done with FILE:// URLs.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* cap the upload speed to 1000 bytes/sec */
    fetch_easy_setopt(fetch, FETCHOPT_MAX_SEND_SPEED_LARGE, (fetch_off_t)1000);
    /* (set some upload options as well) */
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
