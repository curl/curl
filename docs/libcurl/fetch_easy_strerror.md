---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_easy_strerror
Section: 3
Source: libfetch
See-also:
  - fetch_multi_strerror (3)
  - fetch_share_strerror (3)
  - fetch_url_strerror (3)
  - libfetch-errors (3)
Protocol:
  - All
Added-in: 7.12.0
---

# NAME

fetch_easy_strerror - return string describing error code

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

const char *fetch_easy_strerror(FETCHcode errornum);
~~~

# DESCRIPTION

The fetch_easy_strerror(3) function returns a string describing the
FETCHcode error code passed in the argument *errornum*.

Typically applications also appreciate FETCHOPT_ERRORBUFFER(3) for more
specific error descriptions generated at runtime.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    /* set options */
    /* Perform the entire transfer */
    res = fetch_easy_perform(fetch);
    /* Check for errors */
    if(res != FETCHE_OK)
      fprintf(stderr, "fetch_easy_perform() failed: %s\n",
              fetch_easy_strerror(res));
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string.
