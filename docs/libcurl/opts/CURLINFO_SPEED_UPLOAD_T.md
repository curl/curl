---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_SPEED_UPLOAD_T
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SPEED_DOWNLOAD_T (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

CURLINFO_SPEED_UPLOAD_T - get upload speed

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SPEED_UPLOAD_T,
                           curl_off_t *speed);
~~~

# DESCRIPTION

Pass a pointer to a *curl_off_t* to receive the average upload speed that
curl measured for the complete upload. Measured in bytes/second.

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
      curl_off_t speed;
      res = curl_easy_getinfo(curl, CURLINFO_SPEED_UPLOAD_T, &speed);
      if(!res) {
        printf("Upload speed %" CURL_FORMAT_CURL_OFF_T " bytes/sec\n", speed);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
