---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CLOSESOCKETFUNCTION
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CLOSESOCKETDATA (3)
  - CURLOPT_OPENSOCKETFUNCTION (3)
  - CURLMOPT_SOCKETFUNCTION (3)
Protocol:
  - All
Added-in: 7.21.7
---

# NAME

CURLOPT_CLOSESOCKETFUNCTION - callback to socket close replacement

# SYNOPSIS

~~~c
#include <curl/curl.h>

int closesocket_callback(void *clientp, curl_socket_t item);

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CLOSESOCKETFUNCTION,
                          closesocket_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libcurl instead of the *close(3)* or
*closesocket(3)* call when sockets are closed (not for any other file
descriptors). This is pretty much the reverse to the
CURLOPT_OPENSOCKETFUNCTION(3) option. Return 0 to signal success and 1
if there was an error.

The *clientp* pointer is set with
CURLOPT_CLOSESOCKETDATA(3). *item* is the socket libcurl wants to be
closed.

Note that when using multi/share handles, your callback may get invoked even
after the easy handle has been cleaned up. The callback and data is
inherited by a new connection and that connection may live longer
than the transfer itself in the multi/share handle's connection cache.

# NOTES ON IDLE CONNECTIONS

When using the multi interface with a connection cache, applications must
not assume that sockets associated with idle connections behave the same
as active connections.

## Callback life cycle

The callback and CURLOPT_CLOSESOCKETDATA(3) are copied from the *first* easy
handle that creates the connection. Changing this option on a subsequent
easy handle that reuses the same connection has no effect for that
connection. The callback is not invoked when an idle connection is
closed after CURL_CSELECT_ERR. Applications should not rely on the close
callback to be called for every socket that leaves use.

## Readiness events after CURL_POLL_REMOVE

Applications must not assume that receiving readiness events for a socket
implies that libcurl still expects the socket to be reported back via
curl_multi_socket_action(3). Readiness events may occur for reasons
outside libcurl's control, but libcurl provides no API for reporting such
events once a socket has been removed from polling. Applications
integrating with external polling systems must defensively handle
unexpected readiness events.

## Socket callback and idle sockets

After libcurl signals CURL_POLL_REMOVE for a socket, the application must
stop monitoring that socket for read and write events on libcurl's behalf.
libcurl may still retain the connection internally for reuse. When the
socket has been removed, the pointer previously assigned to it with
curl_multi_assign(3) is forgotten by libcurl. Applications must not rely
on *socketp* to track idle connections.

# DEFAULT

Use the standard socket close function.

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static int closesocket(void *clientp, curl_socket_t item)
{
  struct priv *my = clientp;
  printf("our ptr: %p\n", my->custom);

  printf("libcurl wants to close %d now\n", (int)item);
  return 0;
}

int main(void)
{
  struct priv myown;
  CURL *curl = curl_easy_init();

  /* call this function to close sockets */
  curl_easy_setopt(curl, CURLOPT_CLOSESOCKETFUNCTION, closesocket);
  curl_easy_setopt(curl, CURLOPT_CLOSESOCKETDATA, &myown);

  curl_easy_perform(curl);
  curl_easy_cleanup(curl);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
