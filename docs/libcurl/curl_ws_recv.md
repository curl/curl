---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_ws_recv
Section: 3
Source: libfetch
See-also:
  - fetch_easy_getinfo (3)
  - fetch_easy_perform (3)
  - fetch_easy_setopt (3)
  - fetch_ws_send (3)
  - libfetch-ws (3)
Protocol:
  - WS
Added-in: 7.86.0
---

# NAME

fetch_ws_recv - receive WebSocket data

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_ws_recv(FETCH *fetch, void *buffer, size_t buflen,
                      size_t *recv, const struct fetch_ws_frame **meta);
~~~

# DESCRIPTION

Retrieves as much as possible of a received WebSocket data fragment into the
**buffer**, but not more than **buflen** bytes. *recv* is set to the
number of bytes actually stored.

If there is more fragment data to deliver than what fits in the provided
*buffer*, libfetch returns a full buffer and the application needs to call this
function again to continue draining the buffer.

If the function call is successful, the *meta* pointer gets set to point to a
*const struct fetch_ws_frame* that contains information about the received
data. That struct must not be freed and its contents must not be relied upon
anymore once another WebSocket function is called. See the fetch_ws_meta(3) for
details on that struct.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  size_t rlen;
  const struct fetch_ws_frame *meta;
  char buffer[256];
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res = fetch_ws_recv(fetch, buffer, sizeof(buffer), &rlen, &meta);
    if(res)
      printf("error: %s\n", fetch_easy_strerror(res));
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3). If FETCHOPT_ERRORBUFFER(3) was set with fetch_easy_setopt(3)
there can be an error message stored in the error buffer when non-zero is
returned.

Returns **FETCHE_GOT_NOTHING** if the associated connection is closed.

Instead of blocking, the function returns **FETCHE_AGAIN**. The correct
behavior is then to wait for the socket to signal readability before calling
this function again.
