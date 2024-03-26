---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_REDIRECT_COUNT
Section: 3
Source: libcurl
See-also:
  - CURLINFO_REDIRECT_URL (3)
  - CURLOPT_FOLLOWLOCATION (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
---

# NAME

CURLINFO_REDIRECT_COUNT - get the number of redirects

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_REDIRECT_COUNT,
                           long *countp);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the total number of redirections that were
actually followed.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      long redirects;
      curl_easy_getinfo(curl, CURLINFO_REDIRECT_COUNT, &redirects);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.9.7

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
