---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_version
Section: 3
Source: libfetch
See-also:
  - fetch_version_info (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

fetch_version - returns the libfetch version string

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

char *fetch_version();
~~~

# DESCRIPTION

Returns a human readable string with the version number of libfetch and some of
its important components (like OpenSSL version).

We recommend using fetch_version_info(3) instead.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  printf("libfetch version %s\n", fetch_version());
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string. The string resides in a statically
allocated buffer and must not be freed by the caller.
