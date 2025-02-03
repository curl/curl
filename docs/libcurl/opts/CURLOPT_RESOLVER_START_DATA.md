---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RESOLVER_START_DATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PREREQFUNCTION (3)
  - FETCHOPT_RESOLVER_START_FUNCTION (3)
Protocol:
  - All
Added-in: 7.59.0
---

# NAME

FETCHOPT_RESOLVER_START_DATA - pointer passed to the resolver start callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_RESOLVER_START_DATA,
                          void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* is be untouched by libfetch and passed as the third
argument in the resolver start callback set with
FETCHOPT_RESOLVER_START_FUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
static int resolver_start_cb(void *resolver_state, void *reserved,
                             void *userdata)
{
  (void)reserved;
  printf("Received resolver_state=%p userdata=%p\n",
         resolver_state, userdata);
  return 0;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_RESOLVER_START_FUNCTION, resolver_start_cb);
    fetch_easy_setopt(fetch, FETCHOPT_RESOLVER_START_DATA, fetch);
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
