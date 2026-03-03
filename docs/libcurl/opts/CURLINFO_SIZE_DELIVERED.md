---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_SIZE_DELIVERED
Section: 3
Source: libcurl
See-also:
  - CURLINFO_SIZE_DOWNLOAD_T (3)
  - CURLINFO_CONTENT_LENGTH_DOWNLOAD_T (3)
  - CURLOPT_MAXFILESIZE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 8.20.0
---

# NAME

CURLINFO_SIZE_DELIVERED - number of delivered bytes

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_SIZE_DELIVERED,
                           curl_off_t *dlp);
~~~

# DESCRIPTION

Pass a pointer to a *curl_off_t* to receive the total amount of bytes that
were passed on to the write callback in the download. The amount is only for
the latest transfer and gets reset again for each new transfer. This counts
actual payload data, what's also commonly called body. All meta and header
data is excluded from this amount (unless CURLOPT_HEADER(3) is set).

The delivered size may differ from the size retrieved with
CURLINFO_SIZE_DOWNLOAD_T(3) when CURLOPT_ACCEPT_ENCODING(3) is used for
automatic data decompression, as this is then the size of the uncompressed
body while CURLINFO_SIZE_DOWNLOAD_T(3) returns the size of the download.

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

    if(result == CURLE_OK) {
      /* check the size */
      curl_off_t dl;
      result = curl_easy_getinfo(curl, CURLINFO_SIZE_DELIVERED, &dl);
      if(result == CURLE_OK) {
        printf("Stored %" CURL_FORMAT_CURL_OFF_T " bytes\n", dl);
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
