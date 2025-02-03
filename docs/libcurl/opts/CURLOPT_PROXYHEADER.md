---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PROXYHEADER
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADEROPT (3)
  - FETCHOPT_HTTPHEADER (3)
Protocol:
  - All
Added-in: 7.37.0
---

# NAME

FETCHOPT_PROXYHEADER - set of HTTP headers to pass to proxy

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PROXYHEADER,
                          struct fetch_slist *headers);
~~~

# DESCRIPTION

Pass a pointer to a linked list of HTTP headers to pass in your HTTP request
sent to a proxy. The rules for this list is identical to the
FETCHOPT_HTTPHEADER(3) option's.

The headers set with this option is only ever used in requests sent to a proxy
- when there is also a request sent to a host.

The first line in a request (containing the method, usually a GET or POST) is
NOT a header and cannot be replaced using this option. Only the lines
following the request-line are headers. Adding this method line in this list
of headers causes your request to send an invalid header.

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

  struct fetch_slist *list;

  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://proxy.example.com:80");

    list = fetch_slist_append(NULL, "Shoesize: 10");
    list = fetch_slist_append(list, "Accept:");

    fetch_easy_setopt(fetch, FETCHOPT_PROXYHEADER, list);

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
