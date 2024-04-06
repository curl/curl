---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_REFERER
Section: 3
Source: libcurl
See-also:
  - CURLOPT_REFERER (3)
  - curl_easy_getinfo (3)
  - curl_easy_header (3)
  - curl_easy_setopt (3)
Protocol:
  - HTTP
---

# NAME

CURLINFO_REFERER - get the used referrer request header

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_REFERER, char **hdrp);
~~~

# DESCRIPTION

Pass in a pointer to a char pointer and get the referrer header used in the
most recent request.

The **hdrp** pointer is NULL or points to private memory you MUST NOT free -
it gets freed when you call curl_easy_cleanup(3) on the corresponding
CURL handle.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_REFERER, "https://example.org/referrer");
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      char *hdr = NULL;
      curl_easy_getinfo(curl, CURLINFO_REFERER, &hdr);
      if(hdr)
        printf("Referrer header: %s\n", hdr);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.76.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
