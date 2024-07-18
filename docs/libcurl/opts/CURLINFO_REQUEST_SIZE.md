---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_REQUEST_SIZE
Section: 3
Source: libcurl
See-also:
  - CURLINFO_HEADER_SIZE (3)
  - CURLINFO_SIZE_DOWNLOAD_T (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

CURLINFO_REQUEST_SIZE - get size of sent request

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_REQUEST_SIZE, long *sizep);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the total size of the issued
requests. This is so far only for HTTP requests. Note that this may be more
than one request if CURLOPT_FOLLOWLOCATION(3) is enabled.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(res == CURLE_OK) {
      long req;
      res = curl_easy_getinfo(curl, CURLINFO_REQUEST_SIZE, &req);
      if(!res)
        printf("Request size: %ld bytes\n", req);
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
