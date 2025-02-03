---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_APPEND
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_DIRLISTONLY (3)
  - FETCHOPT_RESUME_FROM (3)
  - FETCHOPT_UPLOAD (3)
Protocol:
  - FTP
  - SFTP
Added-in: 7.17.0
---

# NAME

FETCHOPT_APPEND - append to the remote file

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_APPEND, long append);
~~~

# DESCRIPTION

A long parameter set to 1 tells the library to append to the remote file
instead of overwrite it. This is only useful when uploading to an FTP site.

# DEFAULT

0 (disabled)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {

    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/dir/to/newfile");
    fetch_easy_setopt(fetch, FETCHOPT_UPLOAD, 1L);
    fetch_easy_setopt(fetch, FETCHOPT_APPEND, 1L);

    fetch_easy_perform(fetch);
  }
}
~~~

# HISTORY

This option was known as FETCHOPT_FTPAPPEND up to 7.16.4

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
