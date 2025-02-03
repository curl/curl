---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_CRLF
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_CONV_FROM_NETWORK_FUNCTION (3)
  - FETCHOPT_CONV_TO_NETWORK_FUNCTION (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

FETCHOPT_CRLF - CRLF conversion

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_CRLF, long conv);
~~~

# DESCRIPTION

Pass a long. If the value is set to 1 (one), libfetch converts Unix newlines to
CRLF newlines on transfers. Disable this option again by setting the value to
0 (zero).

This is a legacy option of questionable use.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    FETCHcode ret;
    fetch_easy_setopt(fetch, FETCHOPT_URL, "ftp://example.com/");
    fetch_easy_setopt(fetch, FETCHOPT_CRLF, 1L);
    ret = fetch_easy_perform(fetch);
    fetch_easy_cleanup(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
