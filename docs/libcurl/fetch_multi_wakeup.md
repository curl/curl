---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_wakeup
Section: 3
Source: libfetch
See-also:
  - fetch_multi_poll (3)
  - fetch_multi_wait (3)
Protocol:
  - All
Added-in: 7.68.0
---

# NAME

fetch_multi_wakeup - wake up a sleeping fetch_multi_poll call

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_wakeup(FETCHM *multi_handle);
~~~

# DESCRIPTION

This function can be called from any thread and it wakes up a sleeping
fetch_multi_poll(3) call that is currently (or is about to be) waiting
for activity or a timeout.

If the function is called when there is no fetch_multi_poll(3) call, it
causes the next call to return immediately.

Calling this function only guarantees to wake up the current (or the next if
there is no current) fetch_multi_poll(3) call, which means it is possible
that multiple calls to this function wake up the same waiting operation.

This function has no effect on fetch_multi_wait(3) calls.

# %PROTOCOLS%

# EXAMPLE

~~~c
extern int time_to_die(void);
extern int set_something_to_signal_thread_1_to_exit(void);
extern int decide_to_stop_thread1();

int main(void)
{
  FETCH *easy;
  FETCHM *multi;
  int still_running;

  /* add the individual easy handle */
  fetch_multi_add_handle(multi, easy);

  /* this is thread 1 */
  do {
    FETCHMcode mc;
    int numfds;

    mc = fetch_multi_perform(multi, &still_running);

    if(mc == FETCHM_OK) {
      /* wait for activity, timeout or wakeup */
      mc = fetch_multi_poll(multi, NULL, 0, 10000, &numfds);
    }

    if(time_to_die())
      return 1;

  } while(still_running);

  fetch_multi_remove_handle(multi, easy);

  /* this is thread 2 */

  if(decide_to_stop_thread1()) {

    set_something_to_signal_thread_1_to_exit();

    fetch_multi_wakeup(multi);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
