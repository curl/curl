---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_STDERR
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_NOPROGRESS (3)
  - FETCHOPT_VERBOSE (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_STDERR - redirect stderr to another stream

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_STDERR, FILE *stream);
~~~

# DESCRIPTION

Pass a FILE * as parameter. Tell libfetch to use this *stream* instead of
stderr when showing the progress meter and displaying FETCHOPT_VERBOSE(3)
data.

If you are using libfetch as a Windows DLL, this option causes an exception and
a crash in the library since it cannot access a FILE * passed on from the
application. A work-around is to instead use FETCHOPT_DEBUGFUNCTION(3).

# DEFAULT

stderr

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  FILE *filep = fopen("dump", "wb");
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_STDERR, filep);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
