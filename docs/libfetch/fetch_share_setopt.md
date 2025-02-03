---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_share_setopt
Section: 3
Source: libfetch
See-also:
  - fetch_share_cleanup (3)
  - fetch_share_init (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

fetch_share_setopt - set options for a shared object

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHSHcode fetch_share_setopt(FETCHSH *share, FETCHSHoption option, parameter);
~~~

# DESCRIPTION

Set the *option* to *parameter* for the given *share*.

# OPTIONS

## FETCHSHOPT_LOCKFUNC

See FETCHSHOPT_LOCKFUNC(3).

## FETCHSHOPT_UNLOCKFUNC

See FETCHSHOPT_UNLOCKFUNC(3).

## FETCHSHOPT_SHARE

See FETCHSHOPT_SHARE(3).

## FETCHSHOPT_UNSHARE

See FETCHSHOPT_UNSHARE(3).

## FETCHSHOPT_USERDATA

See FETCHSHOPT_USERDATA(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHSHcode sh;
  FETCHSH *share = fetch_share_init();
  sh = fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_CONNECT);
  if(sh)
    printf("Error: %s\n", fetch_share_strerror(sh));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred as *\<fetch/fetch.h\>* defines. See the libfetch-errors(3) man
page for the full list with descriptions.
