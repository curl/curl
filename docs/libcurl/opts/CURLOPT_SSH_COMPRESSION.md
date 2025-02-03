---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_SSH_COMPRESSION
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_ACCEPT_ENCODING (3)
  - FETCHOPT_TRANSFER_ENCODING (3)
Protocol:
  - SFTP
  - SCP
Added-in: 7.56.0
---

# NAME

FETCHOPT_SSH_COMPRESSION - enable SSH compression

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_SSH_COMPRESSION, long enable);
~~~

# DESCRIPTION

Pass a long as parameter set to 1L to enable or 0L to disable.

Enables built-in SSH compression. This is a request, not an order; the server
may or may not do it.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "sftp://example.com");

    /* enable built-in compression */
    fetch_easy_setopt(fetch, FETCHOPT_SSH_COMPRESSION, 1L);

    /* Perform the request */
    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
