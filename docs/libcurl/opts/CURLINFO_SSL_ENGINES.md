---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_SSL_ENGINES
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_SSLENGINE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
Added-in: 7.12.3
---

# NAME

FETCHINFO_SSL_ENGINES - get an slist of OpenSSL crypto-engines

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_SSL_ENGINES,
                           struct fetch_slist **engine_list);
~~~

# DESCRIPTION

Pass the address of a 'struct fetch_slist *' to receive a linked-list of
OpenSSL crypto-engines supported. Note that engines are normally implemented
in separate dynamic libraries. Hence not all the returned engines may be
available at runtime. **NOTE:** you must call fetch_slist_free_all(3)
on the list pointer once you are done with it, as libfetch does not free this
data for you.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    struct fetch_slist *engines;
    res = fetch_easy_getinfo(fetch, FETCHINFO_SSL_ENGINES, &engines);
    if((res == FETCHE_OK) && engines) {
      /* we have a list, free it when done using it */
      fetch_slist_free_all(engines);
    }

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
