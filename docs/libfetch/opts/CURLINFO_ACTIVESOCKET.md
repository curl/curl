---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_ACTIVESOCKET
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_LASTSOCKET (3)
  - FETCHOPT_CONNECT_ONLY (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.45.0
---

# NAME

FETCHINFO_ACTIVESOCKET - get the active socket

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_ACTIVESOCKET,
                           fetch_socket_t *socket);
~~~

# DESCRIPTION

Pass a pointer to a fetch_socket_t to receive the most recently active socket
used for the transfer connection by this fetch session. If the socket is no
longer valid, *FETCH_SOCKET_BAD* is returned. When you are finished working
with the socket, you must call fetch_easy_cleanup(3) as usual on the easy
handle and let libfetch close the socket and cleanup other resources associated
with the handle. This option returns the active socket only after the transfer
is complete, and is typically used in combination with
FETCHOPT_CONNECT_ONLY(3), which skips the transfer phase.

FETCHINFO_ACTIVESOCKET(3) was added as a replacement for
FETCHINFO_LASTSOCKET(3) since that one is not working on all platforms.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_socket_t sockfd;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* Do not do the transfer - only connect to host */
    fetch_easy_setopt(fetch, FETCHOPT_CONNECT_ONLY, 1L);
    res = fetch_easy_perform(fetch);
    if(res != FETCHE_OK) {
      printf("Error: %s\n", fetch_easy_strerror(res));
      fetch_easy_cleanup(fetch);
      return 1;
    }

    /* Extract the socket from the fetch handle */
    res = fetch_easy_getinfo(fetch, FETCHINFO_ACTIVESOCKET, &sockfd);
    if(!res && sockfd != FETCH_SOCKET_BAD) {
      /* operate on sockfd */
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
