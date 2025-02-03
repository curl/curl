---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SOCKOPTFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_OPENSOCKETFUNCTION (3)
  - FETCHOPT_SEEKFUNCTION (3)
  - FETCHOPT_SOCKOPTDATA (3)
Protocol:
  - All
Added-in: 7.16.0
---

# NAME

FETCHOPT_SOCKOPTFUNCTION - callback for setting socket options

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

typedef enum  {
  FETCHSOCKTYPE_IPCXN,  /* socket created for a specific IP connection */
  FETCHSOCKTYPE_ACCEPT, /* socket created by accept() call */
  FETCHSOCKTYPE_LAST    /* never use */
} fetchsocktype;

#define FETCH_SOCKOPT_OK 0
#define FETCH_SOCKOPT_ERROR 1 /* causes libfetch to abort and return
                                FETCHE_ABORTED_BY_CALLBACK */
#define FETCH_SOCKOPT_ALREADY_CONNECTED 2

int sockopt_callback(void *clientp,
                     fetch_socket_t fetchfd,
                     fetchsocktype purpose);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SOCKOPTFUNCTION, sockopt_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

When set, this callback function gets called by libfetch when the socket has
been created, but before the connect call to allow applications to change
specific socket options. The callback's *purpose* argument identifies the
exact purpose for this particular socket:

*FETCHSOCKTYPE_IPCXN* for actively created connections or since 7.28.0
*FETCHSOCKTYPE_ACCEPT* for FTP when the connection was setup with PORT/EPSV
(in earlier versions these sockets were not passed to this callback).

Future versions of libfetch may support more purposes. libfetch passes the newly
created socket descriptor to the callback in the *fetchfd* parameter so
additional setsockopt() calls can be done at the user's discretion.

The *clientp* pointer contains whatever user-defined value set using the
FETCHOPT_SOCKOPTDATA(3) function.

Return *FETCH_SOCKOPT_OK* from the callback on success. Return
*FETCH_SOCKOPT_ERROR* from the callback function to signal an unrecoverable
error to the library and it closes the socket and returns
*FETCHE_COULDNT_CONNECT*. Alternatively, the callback function can return
*FETCH_SOCKOPT_ALREADY_CONNECTED*, to tell libfetch that the socket is
already connected and then libfetch does no attempt to connect. This allows an
application to pass in an already connected socket with
FETCHOPT_OPENSOCKETFUNCTION(3) and then have this function make libfetch
not attempt to connect (again).

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
    int sockfd; /* our custom file descriptor */
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
