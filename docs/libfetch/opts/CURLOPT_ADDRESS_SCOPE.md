---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ADDRESS_SCOPE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_STDERR (3)
Protocol:
  - All
Added-in: 7.19.0
---

# NAME

FETCHOPT_ADDRESS_SCOPE - scope id for IPv6 addresses

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ADDRESS_SCOPE, long scope);
~~~

# DESCRIPTION

Pass a long specifying the scope id value to use when connecting to IPv6 addresses.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <net/if.h> /* for if_nametoindex() */

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    long my_scope_id;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    my_scope_id = if_nametoindex("eth0");
    fetch_easy_setopt(fetch, FETCHOPT_ADDRESS_SCOPE, my_scope_id);
    ret = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
Returns FETCHE_BAD_FUNCTION_ARGUMENT if set to a negative value.
