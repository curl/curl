---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHINFO_CONTENT_TYPE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HEADERFUNCTION (3)
  - fetch_easy_getinfo (3)
  - fetch_easy_header (3)
  - fetch_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.9.4
---

# NAME

FETCHINFO_CONTENT_TYPE - get Content-Type

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_getinfo(FETCH *handle, FETCHINFO_CONTENT_TYPE, char **ct);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the content-type of the downloaded
object. This is the value read from the Content-Type: field. If you get NULL,
it means that the server did not send a valid Content-Type header or that the
protocol used does not support this.

The **ct** pointer is set to NULL or pointing to private memory. You MUST
NOT free it - it gets freed when you call fetch_easy_cleanup(3) on the
corresponding fetch handle.

The modern way to get this header from a response is to instead use the
fetch_easy_header(3) function.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode res;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    res = fetch_easy_perform(fetch);

    if(!res) {
      /* extract the content-type */
      char *ct = NULL;
      res = fetch_easy_getinfo(fetch, FETCHINFO_CONTENT_TYPE, &ct);
      if(!res && ct) {
        printf("Content-Type: %s\n", ct);
      }
    }
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_getinfo(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
