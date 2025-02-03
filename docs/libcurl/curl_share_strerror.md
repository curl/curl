---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_share_strerror
Section: 3
Source: libfetch
See-also:
  - fetch_easy_strerror (3)
  - fetch_multi_strerror (3)
  - fetch_url_strerror (3)
  - libfetch-errors (3)
Protocol:
  - All
Added-in: 7.12.0
---

# NAME

fetch_share_strerror - return string describing error code

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

const char *fetch_share_strerror(FETCHSHcode errornum);
~~~

# DESCRIPTION

The fetch_share_strerror(3) function returns a string describing the
*FETCHSHcode* error code passed in the argument *errornum*.

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

A pointer to a null-terminated string.
