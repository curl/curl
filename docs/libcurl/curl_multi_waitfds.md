---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_waitfds
Section: 3
Source: libfetch
See-also:
  - fetch_multi_perform (3)
  - fetch_multi_poll (3)
  - fetch_multi_wait (3)
  - fetch_multi_fdset (3)
Protocol:
  - All
Added-in: 8.8.0
---

# NAME

fetch_multi_waitfds - extract file descriptor information from a multi handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>
#include <stdlib.h>

FETCHMcode fetch_multi_waitfds(FETCHM *multi,
                             struct fetch_waitfd *ufds,
                             unsigned int size,
                             unsigned int *fd_count);
~~~

# DESCRIPTION

This function extracts *fetch_waitfd* structures which are similar to
*poll(2)*'s *pollfd* structure from a given multi_handle.

These structures can be used for polling on multi_handle file descriptors in a
fashion similar to fetch_multi_poll(3). The fetch_multi_perform(3)
function should be called as soon as one of them is ready to be read from or
written to.

libfetch fills provided *ufds* array up to the *size*.
If a number of descriptors used by the multi_handle is greater than the
*size* parameter then libfetch returns FETCHM_OUT_OF_MEMORY error.

If the *fd_count* argument is not a null pointer, it points to a variable
that on return specifies the number of descriptors used by the multi_handle to
be checked for being ready to read or write.

The client code can pass *size* equal to zero just to get the number of the
descriptors and allocate appropriate storage for them to be used in a
subsequent function call. In this case, *fd_count* receives a number greater
than or equal to the number of descriptors.

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <stdlib.h>

int main(void)
{
  FETCHMcode mc;
  struct fetch_waitfd *ufds;

  FETCHM *multi = fetch_multi_init();

  do {
    /* call fetch_multi_perform() */

    /* get the count of file descriptors from the transfers */
    unsigned int fd_count = 0;

    mc = fetch_multi_waitfds(multi, NULL, 0, &fd_count);

    if(mc != FETCHM_OK) {
      fprintf(stderr, "fetch_multi_waitfds() failed, code %d.\n", mc);
      break;
    }

    if(!fd_count)
      continue; /* no descriptors yet */

    /* allocate storage for our descriptors */
    ufds = malloc(fd_count * sizeof(struct fetch_waitfd));

    /* get wait descriptors from the transfers and put them into array. */
    mc = fetch_multi_waitfds(multi, ufds, fd_count, &fd_count);

    if(mc != FETCHM_OK) {
      fprintf(stderr, "fetch_multi_waitfds() failed, code %d.\n", mc);
      free(ufds);
      break;
    }

    /* Do polling on descriptors in ufds */

    free(ufds);
  } while(!mc);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
