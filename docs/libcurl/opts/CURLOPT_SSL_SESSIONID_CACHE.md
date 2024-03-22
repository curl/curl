---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_SSL_SESSIONID_CACHE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DNS_CACHE_TIMEOUT (3)
  - CURLOPT_MAXAGE_CONN (3)
  - CURLOPT_MAXLIFETIME_CONN (3)
  - CURLOPT_SSLVERSION (3)
Protocol:
  - TLS
TLS-backend:
  - All
---

# NAME

CURLOPT_SSL_SESSIONID_CACHE - use the SSL session-ID cache

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_SSL_SESSIONID_CACHE,
                         long enabled);
~~~

# DESCRIPTION

Pass a long set to 0 to disable libcurl's use of SSL session-ID caching. Set
this to 1 to enable it. By default all transfers are done using the cache
enabled. While nothing ever should get hurt by attempting to reuse SSL
session-IDs, there seem to be or have been broken SSL implementations in the
wild that may require you to disable this in order for you to succeed.

# DEFAULT

1

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* switch off session-id use! */
    curl_easy_setopt(curl, CURLOPT_SSL_SESSIONID_CACHE, 0L);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.16.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
