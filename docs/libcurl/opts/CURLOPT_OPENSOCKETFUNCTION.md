---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_OPENSOCKETFUNCTION
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

FETCHOPT_OPENSOCKETFUNCTION - callback for opening socket

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

typedef enum  {
  FETCHSOCKTYPE_IPCXN,  /* socket created for a specific IP connection */
} fetchsocktype;

struct fetch_sockaddr {
  int family;
  int socktype;
  int protocol;
  unsigned int addrlen;
  struct sockaddr addr;
};

fetch_socket_t opensocket_callback(void *clientp,
                                  fetchsocktype purpose,
                                  struct fetch_sockaddr *address);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_OPENSOCKETFUNCTION, opensocket_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libfetch instead of the *socket(2)*
call. The callback's *purpose* argument identifies the exact purpose for
this particular socket. *FETCHSOCKTYPE_IPCXN* is for IP based connections
and is the only purpose currently used in libfetch. Future versions of libfetch
may support more purposes.

The *clientp* pointer contains whatever user-defined value set using the
FETCHOPT_OPENSOCKETDATA(3) function.

The callback gets the resolved peer address as the *address* argument and
is allowed to modify the address or refuse to connect completely. The callback
function should return the newly created socket or *FETCH_SOCKET_BAD* in
case no connection could be established or another error was detected. Any
additional *setsockopt(2)* calls can of course be done on the socket at
the user's discretion.

If *FETCH_SOCKET_BAD* is returned by the callback then libfetch treats it as a
failed connection and tries to open a socket to connect to a different IP
address associated with the transfer. If there are no more addresses to try
then libfetch fails the transfer with error code *FETCHE_COULDNT_CONNECT*.

You can get the IP address that fetch is opening the socket for by casting
*address-\>addr* to `sockaddr_in` if *address-\>family* is `AF_INET`, or to
`sockaddr_in6` if *address-\>family* is `AF_INET6`. For an example of how that
data can be compared against refer to *docs/examples/block_ip.c*.

If you want to pass in a socket with an already established connection, pass
the socket back with this callback and then use FETCHOPT_SOCKOPTFUNCTION(3) to
signal that it already is connected.

# DEFAULT

The equivalent of this:
~~~c
   return socket(addr->family, addr->socktype, addr->protocol);
~~~

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
