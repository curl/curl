---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CONNECT_ONLY
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPPROXYTUNNEL (3)
  - FETCHOPT_VERBOSE (3)
  - fetch_easy_recv (3)
  - fetch_easy_send (3)
Protocol:
  - All
Added-in: 7.15.2
---

# NAME

FETCHOPT_CONNECT_ONLY - stop when connected to target server

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CONNECT_ONLY, long only);
~~~

# DESCRIPTION

Pass a long. If the parameter equals 1, it tells the library to perform all
the required proxy authentication and connection setup, but no data transfer,
and then return.

The option can be used to simply test a connection to a server, but is more
useful when used with the FETCHINFO_ACTIVESOCKET(3) option to
fetch_easy_getinfo(3) as the library can set up the connection and then
the application can obtain the most recently used socket for special data
transfers.

Since 7.86.0, this option can be set to '2' and if HTTP or WebSocket are used,
libfetch performs the request and reads all response headers before handing
over control to the application.

Transfers marked connect only do not reuse any existing connections and
connections marked connect only are not allowed to get reused.

If the connect only transfer is done using the multi interface, the particular
easy handle must remain added to the multi handle for as long as the
application wants to use it. Once it has been removed with
fetch_multi_remove_handle(3), fetch_easy_send(3) and
fetch_easy_recv(3) do not function.

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 1L);
    ret = fetch_easy_perform(fetch);
    if(ret == FETCHE_OK) {
      /* only connected */
    }
  }
}
~~~

# HISTORY

WS and WSS support added in 7.86.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
