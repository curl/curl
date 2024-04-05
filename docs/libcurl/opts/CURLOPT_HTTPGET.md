---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTPGET
Section: 3
Source: libcurl
Protocol:
  - HTTP
See-also:
  - CURLOPT_NOBODY (3)
  - CURLOPT_POST (3)
  - CURLOPT_UPLOAD (3)
  - curl_easy_reset (3)
---

# NAME

CURLOPT_HTTPGET - ask for an HTTP GET request

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTPGET, long useget);
~~~

# DESCRIPTION

Pass a long. If *useget* is 1, this forces the HTTP request to get back to
using GET. Usable if a POST, HEAD, PUT, etc has been used previously using the
same curl *handle*.

When setting CURLOPT_HTTPGET(3) to 1, libcurl automatically sets
CURLOPT_NOBODY(3) to 0 and CURLOPT_UPLOAD(3) to 0.

Setting this option to zero has no effect. Applications need to explicitly
select which HTTP request method to use, they cannot deselect a method. To
reset a handle to default method, consider curl_easy_reset(3).

# DEFAULT

0

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* use a GET to fetch this */
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Along with HTTP

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, and CURLE_UNKNOWN_OPTION if not.
