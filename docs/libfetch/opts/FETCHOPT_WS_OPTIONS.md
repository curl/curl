---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_WS_OPTIONS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CONNECT_ONLY (3)
  - fetch_ws_recv (3)
  - fetch_ws_send (3)
Protocol:
  - WS
Added-in: 7.86.0
---

# NAME

FETCHOPT_WS_OPTIONS - WebSocket behavior options

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_WS_OPTIONS, long bitmask);
~~~

# DESCRIPTION

Pass a long with a bitmask to tell libfetch about specific WebSocket
behaviors.

To detach a WebSocket connection and use the fetch_ws_send(3) and
fetch_ws_recv(3) functions after the HTTP upgrade procedure, set the
FETCHOPT_CONNECT_ONLY(3) option to 2L.

Available bits in the bitmask

## FETCHWS_RAW_MODE (1)

Deliver "raw" WebSocket traffic to the FETCHOPT_WRITEFUNCTION(3)
callback.

In raw mode, libfetch does not handle pings or any other frame for the
application.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ws://example.com/");
    /* tell fetch we deal with all the WebSocket magic ourselves */
    fetch_easy_setopt(fetch, FETCHOPT_WS_OPTIONS, (long)FETCHWS_RAW_MODE);
    res = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
