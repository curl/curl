---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_IGNORE_CONTENT_LENGTH
Section: 3
Source: libfetch
Protocol:
  - HTTP
  - FTP
See-also:
  - FETCHOPT_HTTP_VERSION (3)
  - FETCHOPT_MAXFILESIZE_LARGE (3)
Added-in: 7.14.1
---

# NAME

FETCHOPT_IGNORE_CONTENT_LENGTH - ignore content length

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_IGNORE_CONTENT_LENGTH,
                          long ignore);
~~~

# DESCRIPTION

If *ignore* is set to 1L, ignore the Content-Length header in the HTTP
response and ignore asking for or relying on it for FTP transfers.

This is useful for doing HTTP transfers with ancient web servers which report
incorrect content length for files over 2 gigabytes. If this option is used,
fetch cannot accurately report progress, and it instead stops the download when
the server ends the connection.

It is also useful with FTP when for example the file is growing while the
transfer is in progress which otherwise unconditionally causes libfetch to
report error.

Only use this option if strictly necessary.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* we know the server is silly, ignore content-length */
    fetch_easy_setopt(fetch, FETCHOPT_IGNORE_CONTENT_LENGTH, 1L);

    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

Support for FTP added in 7.46.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
