---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_MAXREDIRS
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_REDIRECT_COUNT (3)
  - FETCHINFO_REDIRECT_URL (3)
  - FETCHOPT_FOLLOWLOCATION (3)
Protocol:
  - HTTP
Added-in: 7.5
---

# NAME

FETCHOPT_MAXREDIRS - maximum number of redirects allowed

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_MAXREDIRS, long amount);
~~~

# DESCRIPTION

Pass a long. The set number is the redirection limit *amount*. If that
many redirections have been followed, the next redirect triggers the error
(*FETCHE_TOO_MANY_REDIRECTS*). This option only makes sense if the
FETCHOPT_FOLLOWLOCATION(3) is used at the same time.

Setting the limit to 0 makes libfetch refuse any redirect.

Set it to -1 for an infinite number of redirects. This allows your application
to get stuck in never-ending redirect loops.

# DEFAULT

30 (since 8.3.0), it was previously unlimited.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");

    /* enable redirect following */
    fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);

    /* allow three redirects */
    fetch_easy_setopt(fetch, FETCHOPT_MAXREDIRS, 3L);

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
