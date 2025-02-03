---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_nextheader
Section: 3
Source: libfetch
See-also:
  - fetch_easy_header (3)
  - fetch_easy_perform (3)
Protocol:
  - HTTP
Added-in: 7.83.0
---

# NAME

fetch_easy_nextheader - get the next HTTP header

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

struct fetch_header *fetch_easy_nextheader(FETCH *easy,
                                         unsigned int origin,
                                         int request,
                                         struct fetch_header *prev);
~~~

# DESCRIPTION

This function lets an application iterate over all previously received HTTP
headers.

The *origin* argument is for specifying which headers to receive, as a single
HTTP transfer might provide headers from several different places and they may
then have different importance to the user and headers using the same name
might be used. The *origin* is a bitmask for what header sources you want. See
the fetch_easy_header(3) man page for the origin descriptions.

The *request* argument tells libfetch from which request you want headers
from. A single transfer might consist of a series of HTTP requests and this
argument lets you specify which particular individual request you want the
headers from. 0 being the first request and then the number increases for
further redirects or when multi-state authentication is used. Passing in -1 is
a shortcut to "the last" request in the series, independently of the actual
amount of requests used.

It is suggested that you pass in the same **origin** and **request** when
iterating over a range of headers as changing the value mid-loop might give
you unexpected results.

If *prev* is NULL, this function returns a pointer to the first header stored
within the given scope (origin + request).

If *prev* is a pointer to a previously returned header struct,
fetch_easy_nextheader(3) returns a pointer the next header stored within the
given scope. This way, an application can iterate over all available headers.

The memory for the struct this points to, is owned and managed by libfetch and
is associated with the easy handle. Applications must copy the data if they
want it to survive subsequent API calls or the life-time of the easy handle.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  struct fetch_header *prev = NULL;
  struct fetch_header *h;

  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    fetch_easy_perform(fetch);

    /* extract the normal headers from the first request */
    while((h = fetch_easy_nextheader(fetch, FETCHH_HEADER, 0, prev))) {
      printf("%s: %s\n", h->name, h->value);
      prev = h;
    }

    /* extract the normal headers + 1xx + trailers from the last request */
    unsigned int origin = FETCHH_HEADER| FETCHH_1XX | FETCHH_TRAILER;
    while((h = fetch_easy_nextheader(fetch, origin, -1, prev))) {
      printf("%s: %s\n", h->name, h->value);
      prev = h;
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns the next header, or NULL when there are no more
(matching) headers or an error occurred.

If this function returns NULL when *prev* was set to NULL, then there are no
headers available within the scope to return.
