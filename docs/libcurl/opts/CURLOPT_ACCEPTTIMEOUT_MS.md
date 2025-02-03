---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_ACCEPTTIMEOUT_MS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CONNECTTIMEOUT_MS (3)
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_STDERR (3)
Protocol:
  - FTP
Added-in: 7.24.0
---

# NAME

FETCHOPT_ACCEPTTIMEOUT_MS - timeout waiting for FTP server to connect back

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_ACCEPTTIMEOUT_MS, long ms);
~~~

# DESCRIPTION

Pass a long telling libfetch the maximum number of milliseconds to wait for a
server to connect back to libfetch when an active FTP connection is used.

# DEFAULT

60000 milliseconds

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/path/file");

    /* wait no more than 5 seconds for FTP server responses */
    fetch_easy_setopt(fetch, FETCHOPT_ACCEPTTIMEOUT_MS, 5000L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
