---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_CA_CACHE_TIMEOUT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_CAINFO (3)
  - CURLOPT_CAINFO_BLOB (3)
  - CURLOPT_CAPATH (3)
  - CURLOPT_SSL_VERIFYHOST (3)
  - CURLOPT_SSL_VERIFYPEER (3)
Protocol:
  - TLS
TLS-backend:
  - OpenSSL
---

# NAME

CURLOPT_CA_CACHE_TIMEOUT - life-time for cached certificate stores

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_CA_CACHE_TIMEOUT, long age);
~~~

# DESCRIPTION

Pass a long, this sets the timeout in seconds. This tells libcurl the maximum
time any cached certificate store it has in memory may be kept and reused for
new connections. Once the timeout has expired, a subsequent fetch requiring a
certificate has to reload it.

Building a certificate store from a CURLOPT_CAINFO(3) file is a slow
operation so curl may cache the generated certificate store internally to speed
up future connections.

Set to zero to completely disable caching, or set to -1 to retain the cached
store remain forever. By default, libcurl caches this info for 24 hours.

# DEFAULT

86400 (24 hours)

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/foo.bin");

    /* only reuse certificate stores for a short time */
    curl_easy_setopt(curl, CURLOPT_CA_CACHE_TIMEOUT, 60L);

    res = curl_easy_perform(curl);

    /* in this second request, the cache is not used if more than
       sixty seconds passed since the previous connection */
    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

This option was added in curl 7.87.0.

This option is supported by OpenSSL and its forks (since 7.87.0) and Schannel
(since 8.5.0).

# RETURN VALUE

Returns CURLE_OK
