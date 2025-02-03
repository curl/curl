---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_LASTSOCKET
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_ACTIVESOCKET (3)
  - FETCHOPT_CONNECT_ONLY (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.15.2
---

# NAME

FETCHINFO_LASTSOCKET - get the last socket used

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_LASTSOCKET, long *socket);
~~~

# DESCRIPTION

Deprecated since 7.45.0. Use FETCHINFO_ACTIVESOCKET(3) instead.

Pass a pointer to a long to receive the last socket used by this fetch
session. If the socket is no longer valid, -1 is returned. When you finish
working with the socket, you must call fetch_easy_cleanup(3) as usual and
let libfetch close the socket and cleanup other resources associated with the
handle. This is typically used in combination with
FETCHOPT_CONNECT_ONLY(3).

NOTE: this API is deprecated since it is not working on win64 where the SOCKET
type is 64 bits large while its 'long' is 32 bits. Use the
FETCHINFO_ACTIVESOCKET(3) instead, if possible.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    long sockfd; /* does not work on win64 */
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
    res = fetch_easy_getinfo(fetch, FETCHINFO_LASTSOCKET, &sockfd);
    if(!res && sockfd != -1) {
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
