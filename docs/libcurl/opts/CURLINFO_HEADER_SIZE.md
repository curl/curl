---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_HEADER_SIZE
Section: 3
Source: libcurl
See-also:
  - CURLINFO_REQUEST_SIZE (3)
  - CURLINFO_SIZE_DOWNLOAD (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

CURLINFO_HEADER_SIZE - get size of retrieved headers

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_HEADER_SIZE, long *sizep);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the total size of all the headers
received. Measured in number of bytes.

The total includes the size of any received headers suppressed by
CURLOPT_SUPPRESS_CONNECT_HEADERS(3).

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
      long size;
      res = curl_easy_getinfo(curl, CURLINFO_HEADER_SIZE, &size);
      if(!res)
        printf("Header size: %ld bytes\n", size);
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
