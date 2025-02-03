---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_init
Section: 3
Source: libfetch
See-also:
  - fetch_easy_cleanup (3)
  - fetch_easy_duphandle (3)
  - fetch_easy_perform (3)
  - fetch_easy_reset (3)
  - fetch_global_init (3)
  - fetch_multi_init (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_easy_init - create an easy handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCH *fetch_easy_init();
~~~

# DESCRIPTION

This function allocates and returns an easy handle. Such a handle is used as
input to other functions in the easy interface. This call must have a
corresponding call to fetch_easy_cleanup(3) when the operation is complete.

The easy handle is used to hold and control a single network transfer. It is
encouraged to reuse easy handles for repeated transfers.

An alternative way to get a new easy handle is to duplicate an already
existing one with fetch_easy_duphandle(3), which has the upside that it gets
all the options that were set in the source handle set in the new copy as
well.

If you did not already call fetch_global_init(3) before calling this function,
fetch_easy_init(3) does it automatically. This can be lethal in multi-threaded
cases for platforms where fetch_global_init(3) is not thread-safe, and it may
then result in resource problems because there is no corresponding cleanup.

You are strongly advised to not allow this automatic behavior, by calling
fetch_global_init(3) yourself properly. See the description in libfetch(3) of
global environment requirements for details of how to use this function.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

If this function returns NULL, something went wrong and you cannot use the
other fetch functions.
