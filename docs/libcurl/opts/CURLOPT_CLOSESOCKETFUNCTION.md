---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CLOSESOCKETFUNCTION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CLOSESOCKETDATA (3)
  - FETCHOPT_OPENSOCKETFUNCTION (3)
Protocol:
  - All
Added-in: 7.21.7
---

# NAME

FETCHOPT_CLOSESOCKETFUNCTION - callback to socket close replacement

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

int closesocket_callback(void *clientp, fetch_socket_t item);

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CLOSESOCKETFUNCTION,
                          closesocket_callback);
~~~

# DESCRIPTION

Pass a pointer to your callback function, which should match the prototype
shown above.

This callback function gets called by libfetch instead of the *close(3)* or
*closesocket(3)* call when sockets are closed (not for any other file
descriptors). This is pretty much the reverse to the
FETCHOPT_OPENSOCKETFUNCTION(3) option. Return 0 to signal success and 1
if there was an error.

The *clientp* pointer is set with
FETCHOPT_CLOSESOCKETDATA(3). *item* is the socket libfetch wants to be
closed.

# DEFAULT

Use the standard socket close function.

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
