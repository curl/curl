---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_assign
Section: 3
Source: libfetch
See-also:
  - fetch_multi_setopt (3)
  - fetch_multi_socket_action (3)
Protocol:
  - All
Added-in: 7.15.5
---

# NAME

fetch_multi_assign - set data to associate with an internal socket

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_assign(FETCHM *multi_handle, fetch_socket_t sockfd,
                            void *sockptr);
~~~

# DESCRIPTION

This function creates an association in the multi handle between the given
socket and a private pointer of the application. This is designed for
fetch_multi_socket_action(3) uses.

When set, the *sockptr* pointer is passed to all future socket callbacks
for the specific *sockfd* socket.

If the given *sockfd* is not already in use by libfetch, this function
returns an error.

libfetch only keeps one single pointer associated with a socket, so calling
this function several times for the same socket makes the last set pointer get
used.

The idea here being that this association (socket to private pointer) is
something that just about every application that uses this API needs and then
libfetch can just as well do it since it already has the necessary
functionality.

It is acceptable to call this function from your multi callback functions.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHM *multi = fetch_multi_init();
  void *ourstructp; /* pointer to our data */
  fetch_socket_t fd; /* file descriptor to associate our data with */

  /* make our struct pointer associated with socket fd */
  FETCHMcode mc = fetch_multi_assign(multi, fd, ourstructp);
  if(mc)
    printf("error: %s\n", fetch_multi_strerror(mc));
}
~~~

# TYPICAL USAGE

In a typical application you allocate a struct or at least use some kind of
semi-dynamic data for each socket that we must wait for action on when using
the fetch_multi_socket_action(3) approach.

When our socket-callback gets called by libfetch and we get to know about yet
another socket to wait for, we can use fetch_multi_assign(3) to point out the
particular data so that when we get updates about this same socket again, we
do not have to find the struct associated with this socket by ourselves.

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
