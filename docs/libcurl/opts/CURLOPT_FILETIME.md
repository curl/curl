---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_FILETIME
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_FILETIME (3)
  - fetch_easy_getinfo (3)
Protocol:
  - HTTP
  - FTP
  - SFTP
  - FILE
  - SMB
Added-in: 7.5
---

# NAME

FETCHOPT_FILETIME - get the modification time of the remote resource

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_FILETIME, long gettime);
~~~

# DESCRIPTION

Pass a long. If it is 1, libfetch attempts to get the modification time of the
remote document in this operation. This requires that the remote server sends
the time or replies to a time querying command. The fetch_easy_getinfo(3)
function with the FETCHINFO_FILETIME(3) argument can be used after a
transfer to extract the received time (if any).

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
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/path.html");
    /* Ask for filetime */
    fetch_easy_setopt(fetch, FETCHOPT_FILETIME, 1L);
    res = fetch_easy_perform(fetch);
    if(FETCHE_OK == res) {
      long filetime;
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

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
