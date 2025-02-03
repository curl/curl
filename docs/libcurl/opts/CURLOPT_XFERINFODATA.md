---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_XFERINFODATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_NOPROGRESS (3)
  - FETCHOPT_VERBOSE (3)
  - FETCHOPT_XFERINFOFUNCTION (3)
Protocol:
  - All
Added-in: 7.32.0
---

# NAME

FETCHOPT_XFERINFODATA - pointer passed to the progress callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_XFERINFODATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that is untouched by libfetch and passed as the first
argument in the progress callback set with FETCHOPT_XFERINFOFUNCTION(3).

This is an alias for FETCHOPT_PROGRESSDATA(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct progress {
  char *private;
  size_t size;
};

static size_t progress_cb(void *clientp,
                          fetch_off_t dltotal,
                          fetch_off_t dlnow,
                          fetch_off_t ultotal,
                          fetch_off_t ulnow)
{
  struct progress *memory = clientp;
  printf("private ptr: %p\n", memory->private);
  /* use the values */

  return 0; /* all is good */
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct progress data;

    /* pass struct to callback  */
    fetch_easy_setopt(fetch, FETCHOPT_XFERINFODATA, &data);
    fetch_easy_setopt(fetch, FETCHOPT_XFERINFOFUNCTION, progress_cb);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
