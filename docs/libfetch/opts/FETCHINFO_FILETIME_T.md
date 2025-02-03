---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_FILETIME_T
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
Added-in: 7.59.0
---

# NAME

FETCHINFO_FILETIME_T - get the remote time of the retrieved document

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_FILETIME_T,
                           fetch_off_t *timep);
~~~

# DESCRIPTION

Pass a pointer to a fetch_off_t to receive the remote time of the retrieved
document in number of seconds since January 1 1970 in the GMT/UTC time zone.
If you get -1, it can be because of many reasons (it might be unknown, the
server might hide it or the server does not support the command that tells
document time etc) and the time of the document is unknown.

You must ask libfetch to collect this information before the transfer is made,
by using the FETCHOPT_FILETIME(3) option or you unconditionally get a -1 back.

This option is an alternative to FETCHINFO_FILETIME(3) to allow systems with 32
bit long variables to extract dates outside of the 32-bit timestamp range.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    /* Ask for filetime */
    fetch_easy_setopt(fetch, FETCHOPT_FILETIME, 1L);
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      fetch_off_t filetime;
      res = fetch_easy_getinfo(fetch, FETCHINFO_FILETIME_T, &filetime);
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
