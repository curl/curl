---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_SPEED_DOWNLOAD_T
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SIZE_UPLOAD_T (3)
  - CURLINFO_SPEED_UPLOAD_T (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

CURLINFO_SPEED_DOWNLOAD_T - download speed

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SPEED_DOWNLOAD_T,
                           curl_off_t *speed);
~~~

# DESCRIPTION

Pass a pointer to a *curl_off_t* to receive the average download speed
that curl measured for the complete download. Measured in bytes/second.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode result;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* Perform the request */
    result = curl_easy_perform(curl);

    if(!result) {
      curl_off_t speed;
      result = curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD_T, &speed);
      if(!result) {
        printf("Download speed %" CURL_FORMAT_CURL_OFF_T " bytes/sec\n",
               speed);
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
