---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHSHOPT_UNLOCKFUNC
Section: 3
Source: libfetch
See-also:
  - FETCHSHOPT_LOCKFUNC (3)
  - fetch_share_cleanup (3)
  - fetch_share_init (3)
  - fetch_share_setopt (3)
Protocol:
  - All
Added-in: 7.10.3
---

# NAME

FETCHSHOPT_UNLOCKFUNC - mutex unlock callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void unlockcb(FETCH *handle, fetch_lock_data data, void *clientp);

FETCHSHcode fetch_share_setopt(FETCHSH *share, FETCHSHOPT_UNLOCKFUNC, unlockcb);
~~~

# DESCRIPTION

Set a mutex unlock callback for the share object. There is a corresponding
FETCHSHOPT_LOCKFUNC(3) callback called when the mutex is first locked.

The *unlockcb* argument must be a pointer to a function matching the
prototype shown above. The arguments to the callback are:

*handle* is the currently active easy handle in use when the share object
is released.

The *data* argument tells what kind of data libfetch wants to unlock. Make
sure that the callback uses a different lock for each kind of data.

*clientp* is the private pointer you set with FETCHSHOPT_USERDATA(3).
This pointer is not used by libfetch itself.

# %PROTOCOLS%

# EXAMPLE

~~~c
extern void mutex_unlock(FETCH *, fetch_lock_data, void *);

int main(void)
{
  FETCHSHcode sh;
  FETCHSH *share = fetch_share_init();
  sh = fetch_share_setopt(share, FETCHSHOPT_UNLOCKFUNC, mutex_unlock);
  if(sh)
    printf("Error: %s\n", fetch_share_strerror(sh));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred. See libfetch-errors(3) for the full list with
descriptions.
