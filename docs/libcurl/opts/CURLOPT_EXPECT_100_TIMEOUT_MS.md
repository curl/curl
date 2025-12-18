---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_EXPECT_100_TIMEOUT_MS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTPPOST (3)
  - CURLOPT_POST (3)
Protocol:
  - HTTP
Added-in: 7.36.0
---

# NAME

CURLOPT_EXPECT_100_TIMEOUT_MS - timeout for Expect: 100-continue response

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_EXPECT_100_TIMEOUT_MS,
                          long milliseconds);
~~~

# DESCRIPTION

Pass a long to tell libcurl the number of *milliseconds* to wait for a
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
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* wait 3 seconds for 100-continue */
    curl_easy_setopt(curl, CURLOPT_EXPECT_100_TIMEOUT_MS, 3000L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
