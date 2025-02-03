---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_OPENSOCKETDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CLOSESOCKETFUNCTION (3)
  - FETCHOPT_OPENSOCKETFUNCTION (3)
  - FETCHOPT_SOCKOPTFUNCTION (3)
Protocol:
  - All
Added-in: 7.17.1
---

# NAME

FETCHOPT_OPENSOCKETDATA - pointer passed to open socket callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_OPENSOCKETDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that is untouched by libfetch and passed as the first
argument in the open socket callback set with
FETCHOPT_OPENSOCKETFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
/* make libfetch use the already established socket 'sockfd' */

static fetch_socket_t opensocket(void *clientp,
                                fetchsocktype purpose,
                                struct fetch_sockaddr *address)
{
  fetch_socket_t sockfd;
  sockfd = *(fetch_socket_t *)clientp;
  /* the actual externally set socket is passed in via the OPENSOCKETDATA
     option */
  return sockfd;
}

static int sockopt_callback(void *clientp, fetch_socket_t fetchfd,
                            fetchsocktype purpose)
{
  /* This return code was added in libfetch 7.21.5 */
  return FETCH_SOCKOPT_ALREADY_CONNECTED;
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    extern int sockfd; /* the already connected one */

    /* libfetch thinks that you connect to the host
     * and port that you specify in the URL option. */
    fetch_easy_setopt(fetch, FETCHOPT_URL, "http://99.99.99.99:9999");
    /* call this function to get a socket */
    fetch_easy_setopt(fetch, FETCHOPT_OPENSOCKETFUNCTION, opensocket);
    fetch_easy_setopt(fetch, FETCHOPT_OPENSOCKETDATA, &sockfd);

    /* call this function to set options for the socket */
    fetch_easy_setopt(fetch, FETCHOPT_SOCKOPTFUNCTION, sockopt_callback);

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
