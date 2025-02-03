---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_DEBUGDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_STDERR (3)
Protocol:
  - All
Added-in: 7.9.6
---

# NAME

FETCHOPT_DEBUGDATA - pointer passed to the debug callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_DEBUGDATA, void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* to whatever you want passed in to your
FETCHOPT_DEBUGFUNCTION(3) in the last void * argument. This pointer is
not used by libfetch, it is only passed to the callback.

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct data {
  void *custom;
};

static int my_trace(FETCH *handle, fetch_infotype type,
                    char *data, size_t size,
                    void *clientp)
{
  struct data *mine = clientp;
  printf("our ptr: %p\n", mine->custom);

  /* output debug info */
}

int main(void)
{
  FETCH *fetch;
  FETCHcode res;
  struct data my_tracedata;

  fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_DEBUGFUNCTION, my_trace);

    fetch_easy_setopt(fetch, FETCHOPT_DEBUGDATA, &my_tracedata);

    /* the DEBUGFUNCTION has no effect until we enable VERBOSE */
    fetch_easy_setopt(fetch, FETCHOPT_VERBOSE, 1L);

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    res = fetch_easy_perform(fetch);

    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
  return 0;
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
