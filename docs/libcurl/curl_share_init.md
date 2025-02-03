---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_share_init
Section: 3
Source: libfetch
See-also:
  - fetch_share_cleanup (3)
  - fetch_share_setopt (3)
Protocol:
  - All
Added-in: 7.10
---

# NAME

fetch_share_init - create a share object

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHSH *fetch_share_init();
~~~

# DESCRIPTION

This function returns a pointer to a *FETCHSH* handle to be used as input
to all the other share-functions, sometimes referred to as a share handle in
some places in the documentation. This init call MUST have a corresponding
call to fetch_share_cleanup(3) when all operations using the share are
complete.

This *share handle* is what you pass to fetch using the
FETCHOPT_SHARE(3) option with fetch_easy_setopt(3), to make that
specific fetch handle use the data in this share.

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

If this function returns NULL, something went wrong (out of memory, etc.)
and therefore the share object was not created.
