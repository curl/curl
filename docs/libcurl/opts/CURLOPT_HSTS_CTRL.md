---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HSTS_CTRL
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_ALTSVC (3)
  - FETCHOPT_CONNECT_TO (3)
  - FETCHOPT_HSTS (3)
  - FETCHOPT_RESOLVE (3)
Added-in: 7.74.0
---

# NAME

FETCHOPT_HSTS_CTRL - control HSTS behavior

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

#define FETCHHSTS_ENABLE       (1<<0)
#define FETCHHSTS_READONLYFILE (1<<1)

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HSTS_CTRL, long bitmask);
~~~

# DESCRIPTION

HSTS (HTTP Strict Transport Security) means that an HTTPS server can instruct
the client to not contact it again over clear-text HTTP for a certain period
into the future. libfetch then automatically redirects HTTP attempts to such
hosts to instead use HTTPS. This is done by libfetch retaining this knowledge
in an in-memory cache.

Populate the long *bitmask* with the correct set of features to instruct
libfetch how to handle HSTS for the transfers using this handle.

# BITS

## FETCHHSTS_ENABLE

Enable the in-memory HSTS cache for this handle.

## FETCHHSTS_READONLYFILE

Make the HSTS file (if specified) read-only - makes libfetch not save the cache
to the file when closing the handle.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_HSTS_CTRL, (long)FETCHHSTS_ENABLE);
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
