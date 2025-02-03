---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_fdset
Section: 3
Source: libfetch
See-also:
  - fetch_multi_cleanup (3)
  - fetch_multi_init (3)
  - fetch_multi_perform (3)
  - fetch_multi_timeout (3)
  - fetch_multi_wait (3)
  - fetch_multi_waitfds (3)
  - select (2)
Protocol:
  - All
Added-in: 7.9.6
---

# NAME

fetch_multi_fdset - extract file descriptor information from a multi handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_fdset(FETCHM *multi_handle,
                           fd_set *read_fd_set,
                           fd_set *write_fd_set,
                           fd_set *exc_fd_set,
                           int *max_fd);
~~~

# DESCRIPTION

This function extracts file descriptor information from a given multi_handle.
libfetch returns its *fd_set* sets. The application can use these to
select() on, but be sure to *FD_ZERO* them before calling this function as
fetch_multi_fdset(3) only adds its own descriptors, it does not zero or
otherwise remove any others. The fetch_multi_perform(3) function should
be called as soon as one of them is ready to be read from or written to.

The *read_fd_set* argument should point to an object of type **fd_set**
that on returns specifies the file descriptors to be checked for being ready
to read.

The *write_fd_set* argument should point to an object of type **fd_set**
that on return specifies the file descriptors to be checked for being ready to
write.

The *exc_fd_set* argument should point to an object of type **fd_set**
that on return specifies the file descriptors to be checked for error
conditions.

If no file descriptors are set by libfetch, *max_fd* contain -1 when this
function returns. Otherwise it contains the highest descriptor number libfetch
set. When libfetch returns -1 in *max_fd*, it is because libfetch currently
does something that is not possible for your application to monitor with a
socket and unfortunately you can then not know exactly when the current action
is completed using select(). You then need to wait a while before you proceed
and call fetch_multi_perform(3) anyway. How long to wait? Unless
fetch_multi_timeout(3) gives you a lower number, we suggest 100
milliseconds or so, but you may want to test it out in your own particular
conditions to find a suitable value.

When doing select(), you should use fetch_multi_timeout(3) to figure out
how long to wait for action. Call fetch_multi_perform(3) even if no
activity has been seen on the **fd_sets** after the timeout expires as
otherwise internal retries and timeouts may not work as you would think and
want.

If one of the sockets used by libfetch happens to be larger than what can be
set in an **fd_set**, which on POSIX systems means that the file descriptor
is larger than **FD_SETSIZE**, then libfetch tries to not set it. Setting a
too large file descriptor in an **fd_set** implies an out of bounds write
which can cause crashes, or worse. The effect of NOT storing it might possibly
save you from the crash, but makes your program NOT wait for sockets it should
wait for...

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  fd_set fdread;
  fd_set fdwrite;
  fd_set fdexcep;
  int maxfd;
  int rc;
  FETCHMcode mc;
  struct timeval timeout = {1, 0};

  FETCHM *multi = fetch_multi_init();

  do {

    /* call fetch_multi_perform() */

    /* get file descriptors from the transfers */
    mc = fetch_multi_fdset(multi, &fdread, &fdwrite, &fdexcep, &maxfd);

    if(mc != FETCHM_OK) {
      fprintf(stderr, "fetch_multi_fdset() failed, code %d.\n", mc);
      break;
    }

    /* wait for activity on one of the sockets */
    rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &timeout);

  } while(!mc);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
