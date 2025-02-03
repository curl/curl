---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_SIZE_DOWNLOAD
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_SIZE_DOWNLOAD_T (3)
  - FETCHINFO_SIZE_UPLOAD_T (3)
  - FETCHOPT_MAXFILESIZE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

FETCHINFO_SIZE_DOWNLOAD - get the number of downloaded bytes

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_SIZE_DOWNLOAD, double *dlp);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the total amount of bytes that were
downloaded. The amount is only for the latest transfer and gets reset again
for each new transfer. This counts actual payload data, what's also commonly
called body. All meta and header data is excluded and not included in this
number.

FETCHINFO_SIZE_DOWNLOAD_T(3) is a newer replacement that returns a more
sensible variable type.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* Perform the request */
    res = fetch_easy_perform(fetch);

    if(!res) {
      /* check the size */
      double dl;
      res = fetch_easy_getinfo(fetch, FETCHINFO_SIZE_DOWNLOAD, &dl);
      if(!res) {
        printf("Downloaded %.0f bytes\n", dl);
      }
    }
  }
}
~~~

# DEPRECATED

Deprecated since 7.55.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
