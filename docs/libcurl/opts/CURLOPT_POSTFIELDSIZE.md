---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_POSTFIELDSIZE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_POSTFIELDS (3)
  - FETCHOPT_POSTFIELDSIZE_LARGE (3)
Protocol:
  - HTTP
Added-in: 7.2
---

# NAME

FETCHOPT_POSTFIELDSIZE - size of POST data pointed to

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_POSTFIELDSIZE, long size);
~~~

# DESCRIPTION

If you want to post static data to the server without having libfetch do a
strlen() to measure the data size, this option must be used. When this option
is used you can post fully binary data, which otherwise is likely to fail. If
this size is set to -1, libfetch uses strlen() to get the size or relies on the
FETCHOPT_READFUNCTION(3) (if used) to signal the end of data.

If you post more than 2GB, use FETCHOPT_POSTFIELDSIZE_LARGE(3).

# DEFAULT

-1

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <string.h> /* for strlen */

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    const char *data = "data to send";

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* size of the POST data */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDSIZE, (long) strlen(data));

    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDS, data);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
