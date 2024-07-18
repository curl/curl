---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_OPENSOCKETFUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CLOSESOCKETFUNCTION (3)
  - CURLOPT_OPENSOCKETFUNCTION (3)
  - CURLOPT_SOCKOPTFUNCTION (3)
Protocol:
  - All
Added-in: 7.17.1
---

# NAME

CURLOPT_OPENSOCKETFUNCTION - callback for opening socket

# SYNOPSIS

~~~c
#include <curl/curl.h>

typedef enum  {
  CURLSOCKTYPE_IPCXN,  /* socket created for a specific IP connection */
} curlsocktype;

struct curl_sockaddr {
  int family;
  int socktype;
  int protocol;
  unsigned int addrlen;
  struct sockaddr addr;
};

curl_socket_t opensocket_callback(void *clientp,
                                  curlsocktype purpose,
                                  struct curl_sockaddr *address);

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_OPENSOCKETFUNCTION, opensocket_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libcurl instead of the *socket(2)*
call. The callback's *purpose* argument identifies the exact purpose for
this particular socket. *CURLSOCKTYPE_IPCXN* is for IP based connections
and is the only purpose currently used in libcurl. Future versions of libcurl
may support more purposes.

The *clientp* pointer contains whatever user-defined value set using the
CURLOPT_OPENSOCKETDATA(3) function.

The callback gets the resolved peer address as the *address* argument and
is allowed to modify the address or refuse to connect completely. The callback
function should return the newly created socket or *CURL_SOCKET_BAD* in
case no connection could be established or another error was detected. Any
additional *setsockopt(2)* calls can of course be done on the socket at
the user's discretion. A *CURL_SOCKET_BAD* return value from the callback
function signals an unrecoverable error to libcurl and it returns
*CURLE_COULDNT_CONNECT* from the function that triggered this callback.
This return code can be used for IP address block listing.

If you want to pass in a socket with an already established connection, pass
the socket back with this callback and then use
CURLOPT_SOCKOPTFUNCTION(3) to signal that it already is connected.

# DEFAULT

The equivalent of this:
~~~c
   return socket(addr->family, addr->socktype, addr->protocol);
~~~

# %PROTOCOLS%

# EXAMPLE

~~~c
/* make libcurl use the already established socket 'sockfd' */

static curl_socket_t opensocket(void *clientp,
                                curlsocktype purpose,
                                struct curl_sockaddr *address)
{
  curl_socket_t sockfd;
  sockfd = *(curl_socket_t *)clientp;
  /* the actual externally set socket is passed in via the OPENSOCKETDATA
     option */
  return sockfd;
}

static int sockopt_callback(void *clientp, curl_socket_t curlfd,
                            curlsocktype purpose)
{
  /* This return code was added in libcurl 7.21.5 */
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    extern int sockfd; /* the already connected one */
    /* libcurl thinks that you connect to the host
     * and port that you specify in the URL option. */
    curl_easy_setopt(curl, CURLOPT_URL, "http://99.99.99.99:9999");
    /* call this function to get a socket */
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket);
    curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sockfd);

    /* call this function to set options for the socket */
    curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_callback);

    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
