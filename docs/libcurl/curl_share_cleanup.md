---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_share_cleanup
Section: 3
Source: libfetch
See-also:
  - fetch_share_init (3)
  - fetch_share_setopt (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

fetch_share_cleanup - close a shared object

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHSHcode fetch_share_cleanup(FETCHSH *share_handle);
~~~

# DESCRIPTION

This function deletes a shared object. The share handle cannot be used anymore
when this function has been called.

Passing in a NULL pointer in *share_handle* makes this function return
immediately with no action.

Any use of the **share_handle** after this function has been called and have
returned, is illegal.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHSHcode sh;
  FETCHSH *share = fetch_share_init();
  sh = fetch_share_setopt(share, FETCHSHOPT_SHARE, FETCH_LOCK_DATA_CONNECT);
  /* use the share, then ... */
  fetch_share_cleanup(share);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

FETCHSHE_OK (zero) means that the option was set properly, non-zero means an
error occurred as *\<fetch/fetch.h\>* defines. See the libfetch-errors(3) man
page for the full list with descriptions. If an error occurs, then the share
object is not deleted.
