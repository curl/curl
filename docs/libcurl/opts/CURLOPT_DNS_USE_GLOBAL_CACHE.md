---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_DNS_USE_GLOBAL_CACHE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DNS_CACHE_TIMEOUT (3)
  - CURLOPT_SHARE (3)
---

# NAME

CURLOPT_DNS_USE_GLOBAL_CACHE - global DNS cache

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_DNS_USE_GLOBAL_CACHE,
                          long enable);
~~~

# DESCRIPTION

Has no function since 7.62.0. Do not use!

Pass a long. If the *enable* value is 1, it tells curl to use a global DNS
cache that survives between easy handle creations and deletions. This is not
thread-safe and this uses a global variable.

See CURLOPT_SHARE(3) and curl_share_init(3) for the correct way to
share DNS cache between transfers.

# DEFAULT

0

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* switch off the use of a global, thread unsafe, cache */
    curl_easy_setopt(curl, CURLOPT_DNS_USE_GLOBAL_CACHE, 0L);
    ret = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
}

~~~

# AVAILABILITY

Deprecated since 7.11.1. Function removed in 7.62.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
