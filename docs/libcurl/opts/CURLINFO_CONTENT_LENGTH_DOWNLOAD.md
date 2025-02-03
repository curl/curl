---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_CONTENT_LENGTH_DOWNLOAD
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CONTENT_LENGTH_UPLOAD (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.6.1
---

# NAME

FETCHINFO_CONTENT_LENGTH_DOWNLOAD - get content-length of download

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_CONTENT_LENGTH_DOWNLOAD,
                           double *content_length);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the content-length of the download. This
is the value read from the Content-Length: field. Since 7.19.4, this returns
-1 if the size is not known.

FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T(3) is a newer replacement that returns a more
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
      double cl;
      res = fetch_easy_getinfo(fetch, FETCHINFO_CONTENT_LENGTH_DOWNLOAD, &cl);
      if(!res) {
        printf("Size: %.0f\n", cl);
      }
    }
  }
}
~~~

# DEPRECATED

Deprecated since 7.55.0.

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
