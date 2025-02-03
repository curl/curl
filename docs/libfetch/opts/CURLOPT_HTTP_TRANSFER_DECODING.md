---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_HTTP_TRANSFER_DECODING
Section: 3
Source: libfetch
Protocol:
  - HTTP
See-also:
  - FETCHOPT_ACCEPT_ENCODING (3)
  - FETCHOPT_HTTP_CONTENT_DECODING (3)
Added-in: 7.16.2
---

# NAME

FETCHOPT_HTTP_TRANSFER_DECODING - HTTP transfer decoding control

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_HTTP_TRANSFER_DECODING,
                         long enabled);
~~~

# DESCRIPTION

Pass a long to tell libfetch how to act on transfer decoding. If set to zero,
transfer decoding is disabled, if set to 1 it is enabled (default). libfetch
does chunked transfer decoding by default unless this option is set to zero.

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
    fetch_easy_setopt(fetch, FETCHOPT_HTTP_TRANSFER_DECODING, 0L);
    ret = fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
