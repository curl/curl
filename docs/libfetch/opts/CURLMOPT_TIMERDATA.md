---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_TIMERDATA
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_SOCKETFUNCTION (3)
  - FETCHMOPT_TIMERFUNCTION (3)
Protocol:
  - All
Added-in: 7.16.0
---

# NAME

FETCHMOPT_TIMERDATA - custom pointer to pass to timer callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_TIMERDATA, void *pointer);
~~~

# DESCRIPTION

A data **pointer** to pass to the timer callback set with the
FETCHMOPT_TIMERFUNCTION(3) option.

This pointer is not touched by libfetch but is only be passed in to the timer
callback's **clientp** argument.

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
