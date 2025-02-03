---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHSHOPT_USERDATA
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

FETCHSHOPT_USERDATA - pointer passed to the lock and unlock mutex callbacks

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHSHcode fetch_share_setopt(FETCHSH *share, FETCHSHOPT_USERDATA, void *clientp);
~~~

# DESCRIPTION

The *clientp* parameter is held verbatim by libfetch and is passed on as
the *clientp* argument to the callbacks set with
FETCHSHOPT_LOCKFUNC(3) and FETCHSHOPT_UNLOCKFUNC(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
struct secrets {
  void *custom;
};

int main(void)
{
  FETCHSHcode sh;
  struct secrets private_stuff;
  FETCHSH *share = fetch_share_init();
  sh = fetch_share_setopt(share, FETCHSHOPT_USERDATA, &private_stuff);
  if(sh)
    printf("Error: %s\n", fetch_share_strerror(sh));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred. See libfetch-errors(3) for the full list with
descriptions.
