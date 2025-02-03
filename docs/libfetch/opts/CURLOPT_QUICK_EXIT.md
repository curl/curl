---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_QUICK_EXIT
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FAILONERROR (3)
  - FETCHOPT_RESOLVE (3)
Protocol:
  - All
Added-in: 7.87.0
---

# NAME

FETCHOPT_QUICK_EXIT - allow to exit quickly

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_QUICK_EXIT,
                          long value);
~~~

# DESCRIPTION

Pass a long as a parameter, 1L meaning that when recovering from a timeout,
libfetch should skip lengthy cleanups that are intended to avoid all kinds of
leaks (threads etc.), as the caller program is about to call exit() anyway.
This allows for a swift termination after a DNS timeout for example, by
canceling and/or forgetting about a resolver thread, at the expense of a
possible (though short-lived) leak of associated resources.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_QUICK_EXIT, 1L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
