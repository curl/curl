---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_HTTP_VERSION
Section: 3
Source: libcurl
See-also:
  - CURLINFO_RESPONSE_CODE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.50.0
---

# NAME

CURLINFO_HTTP_VERSION - HTTP version used in the transfer

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_HTTP_VERSION, long *p);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the version used in the last http transfer
done using this handle. The returned value is CURL_HTTP_VERSION_1_0,
CURL_HTTP_VERSION_1_1, CURL_HTTP_VERSION_2_0, CURL_HTTP_VERSION_3 or 0 if the
version cannot be determined.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    result = curl_easy_perform(curl);
    if(result == CURLE_OK) {
      long http_version;
      curl_easy_getinfo(curl, CURLINFO_HTTP_VERSION, &http_version);
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
