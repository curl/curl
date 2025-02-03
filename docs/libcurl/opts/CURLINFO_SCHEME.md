---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_SCHEME
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_EFFECTIVE_URL (3)
  - FETCHINFO_PROTOCOL (3)
  - FETCHINFO_RESPONSE_CODE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.52.0
---

# NAME

FETCHINFO_SCHEME - get the URL scheme (sometimes called protocol) used in the connection

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_SCHEME, char **scheme);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to a null-terminated
string holding the URL scheme used for the most recent connection done with
this FETCH **handle**.

The **scheme** pointer is NULL or points to private memory. You MUST NOT
free - it gets freed when you call fetch_easy_cleanup(3) on the corresponding
fetch handle.

The returned scheme might be upper or lowercase. Do comparisons case
insensitively.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    res = fetch_easy_perform(fetch);
    if(res == FETCHE_OK) {
      char *scheme = NULL;
      fetch_easy_getinfo(fetch, FETCHINFO_SCHEME, &scheme);
      if(scheme)
        printf("scheme: %s\n", scheme); /* scheme: HTTP */
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
