---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: FETCHOPT_EXPECT_100_TIMEOUT_MS
Section: 3
Source: libfetch
See-also:
  - FETCHOPT_HTTPPOST (3)
  - FETCHOPT_POST (3)
Protocol:
  - HTTP
Added-in: 7.36.0
---

# NAME

FETCHOPT_EXPECT_100_TIMEOUT_MS - timeout for Expect: 100-continue response

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHcode fetch_easy_setopt(FETCH *handle, FETCHOPT_EXPECT_100_TIMEOUT_MS,
                          long milliseconds);
~~~

# DESCRIPTION

Pass a long to tell libfetch the number of *milliseconds* to wait for a
server response with the HTTP status 100 (Continue), 417 (Expectation Failed)
or similar after sending an HTTP request containing an Expect: 100-continue
header. If this times out before a response is received, the request body is
sent anyway.

# DEFAULT

1000 milliseconds

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    fetch_easy_setopt(fetch, FETCHOPT_URL, "https://example.com");

    /* wait 3 seconds for 100-continue */
    fetch_easy_setopt(fetch, FETCHOPT_EXPECT_100_TIMEOUT_MS, 3000L);

    fetch_easy_perform(fetch);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

fetch_easy_setopt(3) returns a FETCHcode indicating success or error.

FETCHE_OK (0) means everything was OK, non-zero means an error occurred, see
libfetch-errors(3).
