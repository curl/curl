---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_CONTENT_LENGTH_UPLOAD_T
Section: 3
Source: libfetch
See-also:
  - FETCHINFO_CONTENT_LENGTH_DOWNLOAD_T (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

FETCHINFO_CONTENT_LENGTH_UPLOAD_T - get the specified size of the upload

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_CONTENT_LENGTH_UPLOAD_T,
                           fetch_off_t *content_length);
~~~

# DESCRIPTION

Pass a pointer to a *fetch_off_t* to receive the specified size of the
upload. Stores -1 if the size is not known.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* Perform the upload */
    res = fetch_easy_perform(fetch);

    if(!res) {
      /* check the size */
      fetch_off_t cl;
      res = fetch_easy_getinfo(fetch, FETCHINFO_CONTENT_LENGTH_UPLOAD_T, &cl);
      if(!res) {
        printf("Upload size: %" FETCH_FORMAT_FETCH_OFF_T "\n", cl);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
