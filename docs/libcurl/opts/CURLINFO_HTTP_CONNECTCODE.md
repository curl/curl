---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_HTTP_CONNECTCODE
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RESPONSE_CODE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.10.7
---

# NAME

CURLINFO_HTTP_CONNECTCODE - get the CONNECT response code

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_HTTP_CONNECTCODE, long *p);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the last received HTTP proxy response code
to a CONNECT request. The returned value is zero if no such response code was
available.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* typically CONNECT is used to do HTTPS over HTTP proxies */
    curl_easy_setopt(curl, CURLOPT_PROXY, "http://127.0.0.1");
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      long code;
      res = curl_easy_getinfo(curl, CURLINFO_HTTP_CONNECTCODE, &code);
      if(!res && code)
        printf("The CONNECT response code: %03ld\n", code);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
