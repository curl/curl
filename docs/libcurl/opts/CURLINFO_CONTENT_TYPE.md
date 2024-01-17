---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_CONTENT_TYPE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_HEADERFUNCTION (3)
  - curl_easy_getinfo (3)
  - curl_easy_header (3)
  - curl_easy_setopt (3)
---

# NAME

CURLINFO_CONTENT_TYPE - get Content-Type

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_CONTENT_TYPE, char **ct);
~~~

# DESCRIPTION

Pass a pointer to a char pointer to receive the content-type of the downloaded
object. This is the value read from the Content-Type: field. If you get NULL,
it means that the server did not send a valid Content-Type header or that the
protocol used does not support this.

The **ct** pointer is set to NULL or pointing to private memory. You MUST
NOT free it - it gets freed when you call curl_easy_cleanup(3) on the
corresponding CURL handle.

The modern way to get this header from a response is to instead use the
curl_easy_header(3) function.

# PROTOCOLS

HTTP(S)

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    res = curl_easy_perform(curl);

    if(!res) {
      /* extract the content-type */
      char *ct = NULL;
      res = curl_easy_getinfo(curl, CURLINFO_CONTENT_TYPE, &ct);
      if(!res && ct) {
        printf("Content-Type: %s\n", ct);
      }
    }
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.9.4

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
