---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HTTP09_ALLOWED
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HTTP_VERSION (3)
  - CURLOPT_SSLVERSION (3)
---

# NAME

CURLOPT_HTTP09_ALLOWED - allow HTTP/0.9 response

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HTTP09_ALLOWED, long allowed);
~~~

# DESCRIPTION

Pass the long argument *allowed* set to 1L to allow HTTP/0.9 responses.

An HTTP/0.9 response is a server response entirely without headers and only a
body. You can connect to lots of random TCP services and still get a response
that curl might consider to be HTTP/0.9!

# DEFAULT

curl allowed HTTP/0.9 responses by default before 7.66.0

Since 7.66.0, libcurl requires this option set to 1L to allow HTTP/0.9
responses.

# PROTOCOLS

HTTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_HTTP09_ALLOWED, 1L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Option added in 7.64.0, present along with HTTP.

# RETURN VALUE

Returns CURLE_OK if HTTP is supported, and CURLE_UNKNOWN_OPTION if not.
