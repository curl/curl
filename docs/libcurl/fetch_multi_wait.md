---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_wait
Section: 3
Source: libfetch
See-also:
  - fetch_multi_fdset (3)
  - fetch_multi_perform (3)
  - fetch_multi_poll (3)
Protocol:
  - All
Added-in: 7.28.0
---

# NAME

fetch_multi_wait - poll on all easy handles in a multi handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_wait(FETCHM *multi_handle,
                          struct fetch_waitfd extra_fds[],
                          unsigned int extra_nfds,
                          int timeout_ms,
                          int *numfds);
~~~

# DESCRIPTION

fetch_multi_wait(3) polls all file descriptors used by the fetch easy
handles contained in the given multi handle set. It blocks until activity is
detected on at least one of the handles or *timeout_ms* has passed.
Alternatively, if the multi handle has a pending internal timeout that has a
shorter expiry time than *timeout_ms*, that shorter time is being used
instead to make sure timeout accuracy is reasonably kept.

The calling application may pass additional *fetch_waitfd* structures which
are similar to *poll(2)*'s *pollfd* structure to be waited on in the
same call.

On completion, if *numfds* is non-NULL, it gets populated with the total
number of file descriptors on which interesting events occurred. This number
can include both libfetch internal descriptors as well as descriptors provided
in *extra_fds*.

If no extra file descriptors are provided and libfetch has no file descriptor
to offer to wait for, this function returns immediately. (Consider using
fetch_multi_poll(3) to avoid this behavior.)

This function is encouraged to be used instead of select(3) when using the
multi interface to allow applications to easier circumvent the common problem
with 1024 maximum file descriptors.

# fetch_waitfd

~~~c
struct fetch_waitfd {
  fetch_socket_t fd;
  short events;
  short revents;
};
~~~

## FETCH_WAIT_POLLIN

Bit flag to *fetch_waitfd.events* indicating the socket should poll on read
events such as new data received.

## FETCH_WAIT_POLLPRI

Bit flag to *fetch_waitfd.events* indicating the socket should poll on high
priority read events such as out of band data.

## FETCH_WAIT_POLLOUT

Bit flag to *fetch_waitfd.events* indicating the socket should poll on
write events such as the socket being clear to write without blocking.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *easy;
  FETCHM *multi = fetch_multi_init();
  int still_running;

  /* add the individual easy handle */
  fetch_multi_add_handle(multi, easy);

  do {
    FETCHMcode mc;
    int numfds;

    mc = fetch_multi_perform(multi, &still_running);

    if(mc == FETCHM_OK) {
      /* wait for activity, timeout or "nothing" */
      mc = fetch_multi_wait(multi, NULL, 0, 1000, &numfds);
    }

    if(mc != FETCHM_OK) {
      fprintf(stderr, "fetch_multi failed, code %d.\n", mc);
      break;
    }

  } while(still_running);

  fetch_multi_remove_handle(multi, easy);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
