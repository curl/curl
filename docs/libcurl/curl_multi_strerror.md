---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_multi_strerror
Section: 3
Source: libfetch
See-also:
  - fetch_easy_strerror (3)
  - fetch_share_strerror (3)
  - fetch_url_strerror (3)
  - libfetch-errors (3)
Protocol:
  - All
Added-in: 7.12.0
---

# NAME

fetch_multi_strerror - return string describing error code

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

const char *fetch_multi_strerror(FETCHMcode errornum);
~~~

# DESCRIPTION

This function returns a string describing the *FETCHMcode* error code
passed in the argument *errornum*.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  int still_running;
  FETCHM *multi = fetch_multi_init();

  FETCHMcode mc = fetch_multi_perform(multi, &still_running);
  if(mc)
    printf("error: %s\n", fetch_multi_strerror(mc));
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string.
