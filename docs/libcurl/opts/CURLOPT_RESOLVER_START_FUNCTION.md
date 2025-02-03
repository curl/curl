---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_RESOLVER_START_FUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PREREQFUNCTION (3)
  - FETCHOPT_RESOLVER_START_DATA (3)
Protocol:
  - All
Added-in: 7.59.0
---

# NAME

FETCHOPT_RESOLVER_START_FUNCTION - callback called before a new name resolve is started

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

int resolver_start_cb(void *resolver_state, void *reserved, void *userdata);

FETCHcode fetch_easy_setopt(FETCH *handle,
                          FETCHOPT_RESOLVER_START_FUNCTION,
                          resolver_start_cb);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libfetch every time before a new resolve
request is started.

*resolver_state* points to a backend-specific resolver state. Currently only
the ares resolver backend has a resolver state. It can be used to set up any
desired option on the ares channel before it is used, for example setting up
socket callback options.

*reserved* is reserved.

*userdata* is the user pointer set with the
FETCHOPT_RESOLVER_START_DATA(3) option.

The callback must return 0 on success. Returning a non-zero value causes the
resolve to fail.

# DEFAULT

NULL (No callback)

# %PROTOCOLS%

# EXAMPLE

~~~c
static int start_cb(void *resolver_state, void *reserved,
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
    fetch_easy_setopt(fetch, FETCHOPT_RESOLVER_START_FUNCTION, start_cb);
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
