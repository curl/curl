---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTP200ALIASES
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_HTTP09_ALLOWED (3)
  - FETCHOPT_HTTP_VERSION (3)
Added-in: 7.10.3
---

# NAME

FETCHOPT_HTTP200ALIASES - alternative matches for HTTP 200 OK

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTP200ALIASES,
                          struct fetch_slist *aliases);
~~~

# DESCRIPTION

Pass a pointer to a linked list of *aliases* to be treated as valid HTTP 200
responses. Some servers respond with a custom header response line. For
example, SHOUTcast servers respond with "ICY 200 OK". Also some old Icecast
1.3.x servers respond like that for certain user agent headers or in absence
of such. By including this string in your list of aliases, the response gets
treated as a valid HTTP header line such as "HTTP/1.0 200 OK".

The linked list should be a fully valid list of struct fetch_slist structs, and
be properly filled in. Use fetch_slist_append(3) to create the list and
fetch_slist_free_all(3) to clean up an entire list.

The alias itself is not parsed for any version strings. The protocol is
assumed to match HTTP 1.0 when an alias match.

Using this option multiple times makes the last set list override the previous
ones. Set it to NULL to disable its use again.

libfetch does not copy the list, it needs to be kept around until after the
transfer has completed.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct fetch_slist *list;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    list = fetch_slist_append(NULL, "ICY 200 OK");
    list = fetch_slist_append(list, "WEIRDO 99 FINE");

    fetch_easy_setopt(fetch, FETCHOPT_HTTP200ALIASES, list);
    fetch_easy_perform(fetch);
    fetch_slist_free_all(list); /* free the list again */
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
