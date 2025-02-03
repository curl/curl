---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CLOSESOCKETDATA
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CLOSESOCKETFUNCTION (3)
  - FETCHOPT_OPENSOCKETFUNCTION (3)
Protocol:
  - All
Added-in: 7.21.7
---

# NAME

FETCHOPT_CLOSESOCKETDATA - pointer passed to the socket close callback

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CLOSESOCKETDATA,
                          void *pointer);
~~~

# DESCRIPTION

Pass a *pointer* that remains untouched by libfetch and passed as the first
argument in the closesocket callback set with
FETCHOPT_CLOSESOCKETFUNCTION(3).

# DEFAULT

NULL

# %PROTOCOLS%

# EXAMPLE

~~~c
struct priv {
  void *custom;
};

static int closesocket(void *clientp, fetch_socket_t item)
{
  struct priv *my = clientp;
  printf("our ptr: %p\n", my->custom);

  printf("libfetch wants to close %d now\n", (int)item);
  return 0;
}

int main(void)
{
  struct priv myown;
  FETCH *fetch = fetch_easy_init();

  /* call this function to close sockets */
  fetch_easy_setopt(fetch, FETCHOPT_CLOSESOCKETFUNCTION, closesocket);
  fetch_easy_setopt(fetch, FETCHOPT_CLOSESOCKETDATA, &myown);

  fetch_easy_perform(fetch);
  fetch_easy_cleanup(fetch);
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
