---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SUPPRESS_CONNECT_HEADERS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADER (3)
  - FETCHOPT_HTTPPROXYTUNNEL (3)
  - FETCHOPT_PROXY (3)
Protocol:
  - All
Added-in: 7.54.0
---

# NAME

FETCHOPT_SUPPRESS_CONNECT_HEADERS - suppress proxy CONNECT response headers

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SUPPRESS_CONNECT_HEADERS, long onoff);
~~~

# DESCRIPTION

When FETCHOPT_HTTPPROXYTUNNEL(3) is used and a CONNECT request is made,
suppress proxy CONNECT response headers from the user callback functions
FETCHOPT_HEADERFUNCTION(3) and FETCHOPT_WRITEFUNCTION(3).

Proxy CONNECT response headers can complicate header processing since it is
essentially a separate set of headers. You can enable this option to suppress
those headers.

For example let's assume an HTTPS URL is to be retrieved via CONNECT. On
success there would normally be two sets of headers, and each header line sent
to the header function and/or the write function. The data given to the
callbacks would look like this:

~~~c
HTTP/1.1 200 Connection established
{headers}
...

HTTP/1.1 200 OK
Content-Type: application/json
{headers}
...

{body}
...
~~~

However by enabling this option the CONNECT response headers are suppressed,
so the data given to the callbacks would look like this:

~~~c
HTTP/1.1 200 OK
Content-Type: application/json
{headers}
...

{body}
...
~~~

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    fetch_easy_setopt(fetch, FETCHOPT_HEADER, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_PROXY, "http://foo:3128");
    fetch_easy_setopt(fetch, FETCHOPT_HTTPPROXYTUNNEL, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_SUPPRESS_CONNECT_HEADERS, 1L);

    fetch_easy_perform(fetch);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHE_OK or an error such as FETCHE_UNKNOWN_OPTION.
