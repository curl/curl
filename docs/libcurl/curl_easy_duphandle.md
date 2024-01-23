---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: curl_easy_duphandle
Section: 3
Source: libcurl
See-also:
  - curl_easy_cleanup (3)
  - curl_easy_init (3)
  - curl_easy_reset (3)
  - curl_global_init (3)
---

# NAME

curl_easy_duphandle - Clone a libcurl session handle

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURL *curl_easy_duphandle(CURL *handle);
~~~

# DESCRIPTION

This function returns a new curl handle, a duplicate, using all the options
previously set in the input curl *handle*. Both handles can subsequently be
used independently and they must both be freed with curl_easy_cleanup(3).

Any options that the input handle has been told to point to (as opposed to
copy) with previous calls to curl_easy_setopt(3), are pointed to by the new
handle as well. You must therefore make sure to keep the data around until
both handles have been cleaned up.

The new handle does **not** inherit any state information, no connections, no
SSL sessions and no cookies. It also does not inherit any share object states
or options (created as if CURLOPT_SHARE(3) was set to NULL).

If the source handle has HSTS or alt-svc enabled, the duplicate gets data read
data from the main filename to populate the cache.

In multi-threaded programs, this function must be called in a synchronous way,
the input handle may not be in use when cloned.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    CURL *nother;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    nother = curl_easy_duphandle(curl);
    res = curl_easy_perform(nother);
    curl_easy_cleanup(nother);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.9

# RETURN VALUE

If this function returns NULL, something went wrong and no valid handle was
returned.
