---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_SIZE_UPLOAD_T
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SIZE_DOWNLOAD_T (3)
  - CURLINFO_SIZE_UPLOAD (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

CURLINFO_SIZE_UPLOAD_T - get the number of uploaded bytes

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SIZE_UPLOAD_T,
                           curl_off_t *uploadp);
~~~

# DESCRIPTION

Pass a pointer to a *curl_off_t* to receive the total amount of bytes that
were uploaded.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* Perform the request */
    res = curl_easy_perform(curl);

    if(!res) {
      curl_off_t ul;
      res = curl_easy_getinfo(curl, CURLINFO_SIZE_UPLOAD_T, &ul);
      if(!res) {
        printf("Uploaded %" CURL_FORMAT_CURL_OFF_T " bytes\n", ul);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
