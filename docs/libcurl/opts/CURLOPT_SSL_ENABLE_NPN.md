---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_ENABLE_NPN
Section: 3
Source: libcurl
See-also:
  - CURLOPT_SSL_ENABLE_ALPN (3)
  - CURLOPT_SSL_OPTIONS (3)
---

# NAME

CURLOPT_SSL_ENABLE_NPN - use NPN

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_ENABLE_NPN, long npn);
~~~

# DESCRIPTION

Deprecated in 7.86.0. Setting this option has no function.

Pass a long as parameter, 0 or 1 where 1 is for enable and 0 for disable. This
option enables/disables NPN in the SSL handshake (if the SSL backend libcurl
is built to use supports it), which can be used to negotiate http2.

# DEFAULT

1, enabled

# PROTOCOLS

HTTP

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    curl_easy_setopt(curl, CURLOPT_SSL_ENABLE_NPN, 1L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.36.0. Deprecated in 7.86.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
