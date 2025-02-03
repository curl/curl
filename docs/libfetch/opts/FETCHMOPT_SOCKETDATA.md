---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHMOPT_SOCKETDATA
Section: 3
Source: libfetch
See-also:
  - FETCHMOPT_SOCKETFUNCTION (3)
  - FETCHMOPT_TIMERFUNCTION (3)
  - fetch_multi_socket_action (3)
Protocol:
  - All
Added-in: 7.15.4
---

# NAME

FETCHMOPT_SOCKETDATA - custom pointer passed to the socket callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHMcode fetch_multi_setopt(FETCHM *handle, FETCHMOPT_SOCKETDATA, void *pointer);
~~~

# DESCRIPTION

A data *pointer* to pass to the socket callback set with the
FETCHMOPT_SOCKETFUNCTION(3) option.

This pointer is not touched by libfetch but is only passed in as the socket
callback's **clientp** argument.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *ours;
};

static int sock_cb(FETCH *e, fetch_socket_t s, int what, void *cbp, void *sockp)
{
  struct priv *p = sockp;
  printf("my ptr: %p\n", p->ours);

  if(what == FETCH_POLL_REMOVE) {
    /* remove the socket from our collection */
  }
  if(what & FETCH_POLL_IN) {
    /* wait for read on this socket */
  }
  if(what & FETCH_POLL_OUT) {
    /* wait for write on this socket */
  }

  return 0;
}

int main(void)
{
  struct priv setup;
  FETCHM *multi = fetch_multi_init();
  /* ... use socket callback and custom pointer */
  fetch_multi_setopt(multi, FETCHMOPT_SOCKETFUNCTION, sock_cb);
  fetch_multi_setopt(multi, FETCHMOPT_SOCKETDATA, &setup);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns FETCHM_OK.
