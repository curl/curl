---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_NOPROGRESS
Section: 3
Source: libcurl
See-also:
  - CURLOPT_DEBUGFUNCTION (3)
  - CURLOPT_PROGRESSFUNCTION (3)
  - CURLOPT_VERBOSE (3)
  - CURLOPT_XFERINFOFUNCTION (3)
---

# NAME

CURLOPT_NOPROGRESS - switch off the progress meter

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_NOPROGRESS, long onoff);
~~~

# DESCRIPTION

If *onoff* is to 1, it tells the library to shut off the progress meter
completely for requests done with this *handle*. It also prevents the
CURLOPT_XFERINFOFUNCTION(3) or CURLOPT_PROGRESSFUNCTION(3) from
getting called.

# DEFAULT

1, meaning it normally runs without a progress meter.

# PROTOCOLS

All

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* enable progress meter */
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK.
