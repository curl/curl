---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PATH_AS_IS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_STDERR (3)
  - FETCHOPT_URL (3)
  - fetch_url_set (3)
Protocol:
  - All
Added-in: 7.42.0
---

# NAME

FETCHOPT_PATH_AS_IS - do not handle dot-dot sequences

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PATH_AS_IS, long leaveit);
~~~

# DESCRIPTION

Set the long *leaveit* to 1, to explicitly tell libfetch to not alter the
given path before passing it on to the server.

This instructs libfetch to NOT squash sequences of "/../" or "/./" that may
exist in the URL's path part and that is supposed to be removed according to
RFC 3986 section 5.2.4.

Some server implementations are known to (erroneously) require the dot-dot
sequences to remain in the path and some clients want to pass these on in
order to try out server implementations.

By default libfetch normalizes such sequences before using the path.

This is a request for the *first* request libfetch issues. When following
redirects, it may no longer apply.

The corresponding flag for the fetch_url_set(3) function is called
**FETCHU_PATH_AS_IS**.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "https://example.com/../../etc/password");

    fetch_easy_setopt(fetch, FETCHOPT_PATH_AS_IS, 1L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
