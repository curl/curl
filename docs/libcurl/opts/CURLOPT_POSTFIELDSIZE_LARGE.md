---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_POSTFIELDSIZE_LARGE
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_COPYPOSTFIELDS (3)
  - FETCHOPT_POSTFIELDS (3)
  - FETCHOPT_POSTFIELDSIZE (3)
Protocol:
  - HTTP
Added-in: 7.11.1
---

# NAME

FETCHOPT_POSTFIELDSIZE_LARGE - size of POST data pointed to

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_POSTFIELDSIZE_LARGE,
                          fetch_off_t size);
~~~

# DESCRIPTION

If you want to post static data to the server without having libfetch do a
strlen() to measure the data size, this option must be used. When this option
is used you can post fully binary data, which otherwise is likely to fail. If
this size is set to -1, libfetch uses strlen() to get the size or relies on the
FETCHOPT_READFUNCTION(3) (if used) to signal the end of data.

# DEFAULT

-1

# %PROTOCOLS%

# EXAMPLE

~~~c
extern char *large_chunk; /* pointer to somewhere */

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    const char *data = large_chunk;
    fetch_off_t length_of_data; /* set somehow */

    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* size of the POST data */
    fetch_easy_setopt(fetch, FETCHOPT_POSTFIELDSIZE_LARGE, length_of_data);

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
