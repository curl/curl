---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_PRIVATE
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_PRIVATE (3)
  - FETCHOPT_STDERR (3)
  - FETCHOPT_VERBOSE (3)
Protocol:
  - All
Added-in: 7.10.3
---

# NAME

FETCHOPT_PRIVATE - store a private pointer

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_PRIVATE, void *pointer);
~~~

# DESCRIPTION

Pass a void * as parameter, pointing to data that should be associated with
this fetch handle. The pointer can subsequently be retrieved using
fetch_easy_getinfo(3) with the FETCHINFO_PRIVATE(3) option. libfetch itself
never does anything with this data.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct private {
  void *custom;
};

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  struct private secrets;
  if(fetch) {
    struct private *extracted;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* store a pointer to our private struct */
    fetch_easy_setopt(fetch, FETCHOPT_PRIVATE, &secrets);

    fetch_easy_perform(fetch);

    /* we can extract the private pointer again too */
    fetch_easy_getinfo(fetch, FETCHINFO_PRIVATE, &extracted);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
