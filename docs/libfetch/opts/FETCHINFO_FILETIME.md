---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_FILETIME
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_FILETIME (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
  - FTP
  - SFTP
Added-in: 7.5
---

# NAME

FETCHINFO_FILETIME - get the remote time of the retrieved document

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_FILETIME, long *timep);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the remote time of the retrieved document
in number of seconds since January 1 1970 in the GMT/UTC time zone. If you get
-1, it can be because of many reasons (it might be unknown, the server might
hide it or the server does not support the command that tells document time
etc) and the time of the document is unknown.

You must ask libfetch to collect this information before the transfer is made,
by using the FETCHOPT_FILETIME(3) option or you unconditionally get a -1 back.

Consider FETCHINFO_FILETIME_T(3) instead to be able to extract dates beyond the
year 2038 on systems using 32-bit longs (Windows).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");
    /* Ask for filetime */
    fetch_easy_setopt(fetch, FETCHOPT_FILETIME, 1L);
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      long filetime = 0;
      res = fetch_easy_getinfo(fetch, FETCHINFO_FILETIME, &filetime);
      if((FETCHE_OK == res) && (filetime >= 0)) {
        time_t file_time = (time_t)filetime;
        printf("filetime: %s", ctime(&file_time));
      }
    }
    /* always cleanup */
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
