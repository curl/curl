---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_perform
Section: 3
Source: libfetch
See-also:
  - fetch_multi_add_handle (3)
  - fetch_multi_cleanup (3)
  - fetch_multi_fdset (3)
  - fetch_multi_info_read (3)
  - fetch_multi_init (3)
  - fetch_multi_wait (3)
  - libfetch-errors (3)
Protocol:
  - All
Added-in: 7.9.6
---

# NAME

fetch_multi_perform - run all transfers until it would block

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_perform(FETCHM *multi_handle, int *running_handles);
~~~

# DESCRIPTION

This function performs transfers on all the added handles that need attention
in a non-blocking fashion. The easy handles have previously been added to the
multi handle with fetch_multi_add_handle(3).

When an application has found out there is data available for the multi_handle
or a timeout has elapsed, the application should call this function to
read/write whatever there is to read or write right now etc.
fetch_multi_perform(3) returns as soon as the reads/writes are done. This
function does not require that there actually is any data available for
reading or that data can be written, it can be called just in case. It stores
the number of handles that still transfer data in the second argument's
integer-pointer.

If the amount of *running_handles* is changed from the previous call (or
is less than the amount of easy handles you have added to the multi handle),
you know that there is one or more transfers less "running". You can then call
fetch_multi_info_read(3) to get information about each individual
completed transfer, and that returned info includes FETCHcode and more. If an
added handle fails quickly, it may never be counted as a running_handle. You
could use fetch_multi_info_read(3) to track actual status of the added
handles in that case.

When *running_handles* is set to zero (0) on the return of this function,
there is no longer any transfers in progress.

When this function returns error, the state of all transfers are uncertain and
they cannot be continued. fetch_multi_perform(3) should not be called
again on the same multi handle after an error has been returned, unless first
removing all the handles and adding new ones.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  int still_running;
  FETCHM *multi = fetch_multi_init();
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_multi_add_handle(multi, fetch);
    do {
      FETCHMcode mc = fetch_multi_perform(multi, &still_running);

      if(!mc && still_running)
        /* wait for activity, timeout or "nothing" */
        mc = fetch_multi_poll(multi, NULL, 0, 1000, NULL);

      if(mc) {
        fprintf(stderr, "fetch_multi_poll() failed, code %d.\n", (int)mc);
        break;
      }

    /* if there are still transfers, loop */
    } while(still_running);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).

This function returns errors regarding the whole multi stack. Problems on
individual transfers may have occurred even when this function returns
*FETCHM_OK*. Use fetch_multi_info_read(3) to figure out how individual transfers
did.

# TYPICAL USAGE

Most applications use fetch_multi_poll(3) to make libfetch wait for
activity on any of the ongoing transfers. As soon as one or more file
descriptor has activity or the function times out, the application calls
fetch_multi_perform(3).
