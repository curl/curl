---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_VERBOSE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_ERRORBUFFER (3)
  - CURLOPT_STDERR (3)
  - curl_global_trace (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

CURLOPT_VERBOSE - verbose mode

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_VERBOSE, long onoff);
~~~

# DESCRIPTION

Set the *onoff* parameter to 1 to make the library display a lot of
verbose information about its operations on this *handle*. Useful for
libcurl and/or protocol debugging and understanding. The verbose information
is sent to stderr, or the stream set with CURLOPT_STDERR(3).

You hardly ever want this enabled in production use, you almost always want
this used when you debug/report problems.

To also get all the protocol data sent and received, consider using the
CURLOPT_DEBUGFUNCTION(3).

# DEFAULT

0, meaning disabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* ask libcurl to show us the verbose output */
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
