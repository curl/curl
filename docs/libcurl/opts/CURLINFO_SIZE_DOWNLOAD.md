---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_SIZE_DOWNLOAD
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SIZE_DOWNLOAD_T (3)
  - CURLINFO_SIZE_UPLOAD_T (3)
  - CURLOPT_MAXFILESIZE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
---

# NAME

CURLINFO_SIZE_DOWNLOAD - get the number of downloaded bytes

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SIZE_DOWNLOAD, double *dlp);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the total amount of bytes that were
downloaded. The amount is only for the latest transfer and gets reset again
for each new transfer. This counts actual payload data, what's also commonly
called body. All meta and header data is excluded and not included in this
number.

CURLINFO_SIZE_DOWNLOAD_T(3) is a newer replacement that returns a more
sensible variable type.

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
      double dl;
      res = curl_easy_getinfo(curl, CURLINFO_SIZE_DOWNLOAD, &dl);
      if(!res) {
        printf("Downloaded %.0f bytes\n", dl);
      }
    }
  }
}
~~~

# AVAILABILITY

Added in 7.4.1. Deprecated since 7.55.0.

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
