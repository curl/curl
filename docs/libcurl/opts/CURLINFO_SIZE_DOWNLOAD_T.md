---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_SIZE_DOWNLOAD_T
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SIZE_DOWNLOAD (3)
  - CURLINFO_SIZE_UPLOAD_T (3)
  - CURLOPT_MAXFILESIZE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.55.0
---

# NAME

CURLINFO_SIZE_DOWNLOAD_T - get the number of downloaded bytes

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SIZE_DOWNLOAD_T,
                           curl_off_t *dlp);
~~~

# DESCRIPTION

Pass a pointer to a *curl_off_t* to receive the total amount of bytes that
were downloaded. The amount is only for the latest transfer and gets reset
again for each new transfer. This counts actual payload data, what's also
commonly called body. All meta and header data is excluded from this amount.

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
      /* check the size */
      curl_off_t dl;
      res = curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD_T, &dl);
      if(!res) {
        printf("Downloaded %" CURL_FORMAT_CURL_OFF_T " bytes\n", dl);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
