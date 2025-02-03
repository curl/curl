---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_url_strerror
Section: 3
Source: libfetch
See-also:
  - fetch_easy_strerror (3)
  - fetch_multi_strerror (3)
  - fetch_share_strerror (3)
  - fetch_url_get (3)
  - fetch_url_set (3)
  - libfetch-errors (3)
Protocol:
  - All
Added-in: 7.80.0
---

# NAME

fetch_url_strerror - return string describing error code

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

const char *fetch_url_strerror(FETCHUcode errornum);
~~~

# DESCRIPTION

This function returns a string describing the FETCHUcode error code passed in
the argument *errornum*.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHUcode rc;
  FETCHU *url = fetch_url();
  rc = fetch_url_set(url, FETCHUPART_URL, "https://example.com", 0);
  if(rc)
    printf("URL error: %s\n", fetch_url_strerror(rc));
  fetch_url_cleanup(url);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

A pointer to a null-terminated string.
