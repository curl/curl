---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHSHOPT_LOCKFUNC
Section: 3
Source: libfetch
See-also:
  - FETCHSHOPT_UNLOCKFUNC (3)
  - fetch_share_cleanup (3)
  - fetch_share_init (3)
  - fetch_share_setopt (3)
Protocol:
  - All
Added-in: 7.10.3
---

# NAME

FETCHSHOPT_LOCKFUNC - mutex lock callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void lockcb(FETCH *handle, fetch_lock_data data, fetch_lock_access access,
            void *clientp);

FETCHSHcode fetch_share_setopt(FETCHSH *share, FETCHSHOPT_LOCKFUNC, lockcb);
~~~

# DESCRIPTION

Set a mutex lock callback for the share object, to allow it to get used by
multiple threads concurrently. There is a corresponding
FETCHSHOPT_UNLOCKFUNC(3) callback called when the mutex is again released.

The *lockcb* argument must be a pointer to a function matching the
prototype shown above. The arguments to the callback are:

*handle* is the currently active easy handle in use when the share object
is intended to get used.

The *data* argument tells what kind of data libfetch wants to lock. Make
sure that the callback uses a different lock for each kind of data.

*access* defines what access type libfetch wants, shared or single.

*clientp* is the private pointer you set with FETCHSHOPT_USERDATA(3).
This pointer is not used by libfetch itself.

# %PROTOCOLS%

# EXAMPLE

~~~c
extern void mutex_lock(FETCH *handle, fetch_lock_data data,
                       fetch_lock_access access, void *clientp);

int main(void)
{
  FETCHSHcode sh;
  FETCHSH *share = fetch_share_init();
  sh = fetch_share_setopt(share, FETCHSHOPT_LOCKFUNC, mutex_lock);
  if(sh)
    printf("Error: %s\n", fetch_share_strerror(sh));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred. See libfetch-errors(3) for the full list with
descriptions.
