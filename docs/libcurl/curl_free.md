---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_free
Section: 3
Source: libfetch
See-also:
  - fetch_easy_escape (3)
  - fetch_easy_unescape (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_free - reclaim memory that has been obtained through a libfetch call

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void fetch_free(void *ptr);
~~~

# DESCRIPTION

fetch_free reclaims memory that has been obtained through a libfetch call. Use
fetch_free(3) instead of free() to avoid anomalies that can result from
differences in memory management between your application and libfetch.

Passing in a NULL pointer in *ptr* makes this function return immediately
with no action.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  char *width = fetch_getenv("COLUMNS");
  if(width) {
    /* it was set */
    fetch_free(width);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

None
