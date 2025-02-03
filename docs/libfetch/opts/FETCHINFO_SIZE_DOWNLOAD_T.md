---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_SIZE_DOWNLOAD_T
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_SIZE_DOWNLOAD (3)
  - FETCHINFO_SIZE_UPLOAD_T (3)
  - FETCHOPT_MAXFILESIZE (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

FETCHINFO_SIZE_DOWNLOAD_T - get the number of downloaded bytes

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_SIZE_DOWNLOAD_T,
                           fetch_off_t *dlp);
~~~

# DESCRIPTION

Pass a pointer to a *fetch_off_t* to receive the total amount of bytes that
were downloaded. The amount is only for the latest transfer and gets reset
again for each new transfer. This counts actual payload data, what's also
commonly called body. All meta and header data is excluded from this amount.

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
      fetch_off_t dl;
      res = fetch_easy_getinfo(fetch, FETCHINFO_SIZE_DOWNLOAD_T, &dl);
      if(!res) {
        printf("Downloaded %" FETCH_FORMAT_FETCH_OFF_T " bytes\n", dl);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
