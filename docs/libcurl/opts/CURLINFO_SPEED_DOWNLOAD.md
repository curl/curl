---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_SPEED_DOWNLOAD
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SIZE_UPLOAD_T (3)
  - CURLINFO_SPEED_UPLOAD (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.4.1
---

# NAME

CURLINFO_SPEED_DOWNLOAD - get download speed

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SPEED_DOWNLOAD,
                           double *speed);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the average download speed that curl
measured for the complete download. Measured in bytes/second.

CURLINFO_SPEED_DOWNLOAD_T(3) is a newer replacement that returns a more
sensible variable type.

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
      double speed;
      res = curl_easy_getinfo(curl, CURLINFO_SPEED_DOWNLOAD, &speed);
      if(!res) {
        printf("Download speed %.0f bytes/sec\n", speed);
      }
    }
  }
}
~~~

# DEPRECATED

Deprecated since 7.55.0.

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
