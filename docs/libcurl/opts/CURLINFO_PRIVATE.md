---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_PRIVATE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_PRIVATE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.10.3
---

# NAME

FETCHINFO_PRIVATE - get the private pointer

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_PRIVATE, char **private);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the pointer to the private data
associated with the fetch handle (set with the FETCHOPT_PRIVATE(3)).
Please note that for internal reasons, the value is returned as a char
pointer, although effectively being a 'void *'.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    void *pointer = (void *)0x2345454;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/foo.bin");

    /* set the private pointer */
    fetch_easy_setopt(fetch, FETCHOPT_PRIVATE, pointer);
    res = fetch_easy_perform(fetch);

    /* extract the private pointer again */
    res = fetch_easy_getinfo(fetch, FETCHINFO_PRIVATE, &pointer);

    if(res)
      printf("error: %s\n", fetch_easy_strerror(res));

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
