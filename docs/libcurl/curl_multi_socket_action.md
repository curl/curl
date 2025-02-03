---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_socket_action
Section: 3
Source: libfetch
See-also:
  - fetch_multi_cleanup (3)
  - fetch_multi_fdset (3)
  - fetch_multi_info_read (3)
  - fetch_multi_init (3)
  - the hiperfifo.c example
Protocol:
  - All
Added-in: 7.15.4
---

# NAME

fetch_multi_socket_action - read/write available data given an action

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_socket_action(FETCHM *multi_handle,
                                   fetch_socket_t sockfd,
                                   int ev_bitmask,
                                   int *running_handles);
~~~

# DESCRIPTION

When the application has detected action on a socket handled by libfetch, it
should call fetch_multi_socket_action(3) with the **sockfd** argument
set to the socket with the action. When the events on a socket are known, they
can be passed as an events bitmask **ev_bitmask** by first setting
**ev_bitmask** to 0, and then adding using bitwise OR (|) any combination of
events to be chosen from FETCH_CSELECT_IN, FETCH_CSELECT_OUT or
FETCH_CSELECT_ERR. When the events on a socket are unknown, pass 0 instead, and
libfetch tests the descriptor internally. It is also permissible to pass
FETCH_SOCKET_TIMEOUT to the **sockfd** parameter in order to initiate the
whole process or when a timeout occurs.

At return, **running_handles** points to the number of running easy handles
within the multi handle. When this number reaches zero, all transfers are
complete/done. When you call fetch_multi_socket_action(3) on a specific
socket and the counter decreases by one, it DOES NOT necessarily mean that
this exact socket/transfer is the one that completed. Use
fetch_multi_info_read(3) to figure out which easy handle that completed.

The fetch_multi_socket_action(3) function informs the application about
updates in the socket (file descriptor) status by doing none, one, or multiple
calls to the socket callback function set with the
FETCHMOPT_SOCKETFUNCTION(3) option to fetch_multi_setopt(3). They
update the status with changes since the previous time the callback was
called.

Get the timeout time by setting the FETCHMOPT_TIMERFUNCTION(3) option
with fetch_multi_setopt(3). Your application then gets called with
information on how long to wait for socket actions at most before doing the
timeout action: call the fetch_multi_socket_action(3) function with the
**sockfd** argument set to FETCH_SOCKET_TIMEOUT. You can also use the
fetch_multi_timeout(3) function to poll the value at any given time, but
for an event-based system using the callback is far better than relying on
polling the timeout value.

When this function returns error, the state of all transfers are uncertain and
they cannot be continued. fetch_multi_socket_action(3) should not be
called again on the same multi handle after an error has been returned, unless
first removing all the handles and adding new ones.

# TYPICAL USAGE

1. Create a multi handle

2. Set the socket callback with FETCHMOPT_SOCKETFUNCTION(3)

3. Set the timeout callback with FETCHMOPT_TIMERFUNCTION(3), to get to
know what timeout value to use when waiting for socket activities.

4. Add easy handles with fetch_multi_add_handle()

5. Provide some means to manage the sockets libfetch is using, so you can check
them for activity. This can be done through your application code, or by way
of an external library such as libevent or glib.

6. Call fetch_multi_socket_action(..., FETCH_SOCKET_TIMEOUT, 0, ...)
to kickstart everything. To get one or more callbacks called.

7. Wait for activity on any of libfetch's sockets, use the timeout value your
callback has been told.

8, When activity is detected, call fetch_multi_socket_action() for the
socket(s) that got action. If no activity is detected and the timeout expires,
call fetch_multi_socket_action(3) with *FETCH_SOCKET_TIMEOUT*.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  /* the event-library gets told when there activity on the socket 'fd',
     which we translate to a call to fetch_multi_socket_action() */
  int running;
  FETCHM *multi; /* the stack we work with */
  int fd; /* the descriptor that had action */
  int bitmask; /* what activity that happened */
  FETCHMcode mc = fetch_multi_socket_action(multi, fd, bitmask, &running);
  if(mc)
    printf("error: %s\n", fetch_multi_strerror(mc));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
