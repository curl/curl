---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_AUTOREFERER
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_EFFECTIVE_URL (3)
  - FETCHINFO_REDIRECT_URL (3)
  - FETCHINFO_REFERER (3)
  - FETCHOPT_FOLLOWLOCATION (3)
  - FETCHOPT_REFERER (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

FETCHOPT_AUTOREFERER - automatically update the referer header

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_AUTOREFERER, long autorefer);
~~~

# DESCRIPTION

Pass a long parameter set to 1 to enable this. When enabled, libfetch
automatically sets the Referer: header field in HTTP requests to the full URL
when it follows a Location: redirect to a new destination.

The automatic referer is set to the full previous URL even when redirects are
done cross-origin or following redirects to insecure protocols. This is
considered a minor privacy leak by some.

With FETCHINFO_REFERER(3), applications can extract the actually used
referer header after the transfer.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* follow redirects */
    fetch_easy_setopt(fetch, FETCHOPT_FOLLOWLOCATION, 1L);

    /* set Referer: automatically when following redirects */
    fetch_easy_setopt(fetch, FETCHOPT_AUTOREFERER, 1L);

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
