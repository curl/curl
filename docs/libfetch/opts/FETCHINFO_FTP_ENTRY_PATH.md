---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_FTP_ENTRY_PATH
Section: 3
Source: libfetch
See-also:
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - FTP
Added-in: 7.15.4
---

# NAME

FETCHINFO_FTP_ENTRY_PATH - get entry path in FTP server

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_FTP_ENTRY_PATH, char **path);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive a pointer to a string holding the
path of the entry path. That is the initial path libfetch ended up in when
logging on to the remote FTP server. This stores a NULL as pointer if
something is wrong.

The **path** pointer is NULL or points to private memory. You MUST NOT free
- it gets freed when you call fetch_easy_cleanup(3) on the corresponding fetch
handle.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com");

    res = fetch_easy_perform(fetch);

    if(!res) {
      /* extract the entry path */
      char *ep = NULL;
      res = fetch_easy_getinfo(fetch, FETCHINFO_FTP_ENTRY_PATH, &ep);
      if(!res && ep) {
        printf("Entry path was: %s\n", ep);
      }
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# HISTORY

Works for SFTP since 7.21.4

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
