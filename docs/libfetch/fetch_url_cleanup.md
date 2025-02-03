---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_url_cleanup
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FETCHU (3)
  - fetch_url (3)
  - fetch_url_dup (3)
  - fetch_url_get (3)
  - fetch_url_set (3)
Protocol:
  - All
Added-in: 7.62.0
---

# NAME

fetch_url_cleanup - free the URL handle

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void fetch_url_cleanup(FETCHU *handle);
~~~

# DESCRIPTION

Frees all the resources associated with the given *FETCHU* handle.

Passing in a NULL pointer in *handle* makes this function return
immediately with no action.

Any use of the **handle** after this function has been called and have
returned, is illegal.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCHU *url = fetch_url();
  fetch_url_set(url, FETCHUPART_URL, "https://example.com", 0);
  fetch_url_cleanup(url);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

none
