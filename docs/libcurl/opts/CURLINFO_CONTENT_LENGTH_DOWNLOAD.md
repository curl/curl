---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_CONTENT_LENGTH_DOWNLOAD
Section: 3
Source: libcurl
See-also:
  - CURLINFO_CONTENT_LENGTH_UPLOAD (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.6.1
---

# NAME

CURLINFO_CONTENT_LENGTH_DOWNLOAD - get content-length of download

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD,
                           double *content_length);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the content-length of the download. This
is the value read from the Content-Length: field. This returns -1 if the size
is not known.

CURLINFO_CONTENT_LENGTH_DOWNLOAD_T(3) is a newer replacement that returns a more
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
      /* check the size */
      double cl;
      res = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &cl);
      if(!res) {
        printf("Size: %.0f\n", cl);
      }
    }
  }
}
~~~

# DEPRECATED

Deprecated since 7.55.0.

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
