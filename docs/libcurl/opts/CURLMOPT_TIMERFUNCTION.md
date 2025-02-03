---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_TIMERFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_SOCKETFUNCTION (3)
  - FETCHMOPT_TIMERDATA (3)
Protocol:
  - All
Added-in: 7.16.0
---

# NAME

FETCHMOPT_TIMERFUNCTION - callback to receive timeout values

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

int timer_callback(FETCHM *multi,    /* multi handle */
                   long timeout_ms, /* timeout in number of ms */
                   void *clientp);  /* private callback pointer */

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_TIMERFUNCTION, timer_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

Certain features, such as timeouts and retries, require you to call libfetch
even when there is no activity on the file descriptors.

Your callback function **timer_callback** should install a single
non-repeating timer with an expire time of **timeout_ms** milliseconds. When
that timer fires, call either fetch_multi_socket_action(3) or
fetch_multi_perform(3), depending on which interface you use.

If this callback is called when a timer is already running, this new expire
time *replaces* the former timeout. The application should then effectively
cancel the old timeout and set a new timeout using this new expire time.

A **timeout_ms** value of -1 passed to this callback means you should delete
the timer. All other values are valid expire times in number of milliseconds.

The **timer_callback** is called when the timeout expire time is changed.

The **clientp** pointer is set with FETCHMOPT_TIMERDATA(3).

The timer callback should return 0 on success, and -1 on error. If this
callback returns error, **all** transfers currently in progress in this multi
handle are aborted and made to fail.

This callback can be used instead of, or in addition to,
fetch_multi_timeout(3).

**WARNING:** do not call libfetch directly from within the callback itself when
the **timeout_ms** value is zero, since it risks triggering an unpleasant
recursive behavior that immediately calls another call to the callback with a
zero timeout...

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static int timerfunc(FETCHM *multi, long timeout_ms, void *clientp)
{
  struct priv *mydata = clientp;
  printf("our ptr: %p\n", mydata->custom);

  if(timeout_ms) {
    /* this is the new single timeout to wait for */
  }
  else {
    /* delete the timeout, nothing to wait for now */
  }
}

int main(void)
{
  struct priv mydata;
  FETCHM *multi = fetch_multi_init();
  fetch_multi_setopt(multi, FETCHMOPT_TIMERFUNCTION, timerfunc);
  fetch_multi_setopt(multi, FETCHMOPT_TIMERDATA, &mydata);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_multi_setopt(3) returns a FETCHMcode indicating success or error.

FETCHM_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
