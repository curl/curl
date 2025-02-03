---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_getenv
Section: 3
Source: libfetch
See-also:
  - getenv (3C)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_getenv - return value for environment name

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

char *fetch_getenv(const char *name);
~~~

# DESCRIPTION

fetch_getenv() is a portable wrapper for the getenv() function, meant to
emulate its behavior and provide an identical interface for all operating
systems libfetch builds on (including Windows).

You must fetch_free(3) the returned string when you are done with it.

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

A pointer to a null-terminated string or NULL if it failed to find the
specified name.

# NOTE

Under Unix operating systems, there is no point in returning an allocated
memory, although other systems does not work properly if this is not done. The
Unix implementation thus suffers slightly from the drawbacks of other systems.
