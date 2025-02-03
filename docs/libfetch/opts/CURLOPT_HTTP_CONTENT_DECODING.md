---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTP_CONTENT_DECODING
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_ACCEPT_ENCODING (3)
  - FETCHOPT_DEBUGFUNCTION (3)
  - FETCHOPT_STDERR (3)
Added-in: 7.16.2
---

# NAME

FETCHOPT_HTTP_CONTENT_DECODING - HTTP content decoding control

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTP_CONTENT_DECODING,
                          long enabled);
~~~

# DESCRIPTION

Pass a long to tell libfetch how to act on content decoding. If set to zero,
content decoding is disabled. If set to 1 it is enabled. libfetch has no
default content decoding but requires you to use
FETCHOPT_ACCEPT_ENCODING(3) for that.

# DEFAULT

1

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_HTTP_CONTENT_DECODING, 0L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
