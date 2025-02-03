---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FTP_USE_PRET
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FTP_USE_EPRT (3)
  - FETCHOPT_FTP_USE_EPSV (3)
Protocol:
  - FTP
Added-in: 7.20.0
---

# NAME

FETCHOPT_FTP_USE_PRET - use PRET for FTP

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FTP_USE_PRET, long enable);
~~~

# DESCRIPTION

Pass a long. If the value is 1, it tells fetch to send a PRET command before
PASV (and EPSV). Certain FTP servers, mainly drftpd, require this non-standard
command for directory listings as well as up and downloads in PASV mode. Has
no effect when using the active FTP transfers mode.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL,
                     "ftp://example.com/old-server/file.txt");

    /* a drftpd server, do it */
    fetch_easy_setopt(fetch, FETCHOPT_FTP_USE_PRET, 1L);

    res = fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
