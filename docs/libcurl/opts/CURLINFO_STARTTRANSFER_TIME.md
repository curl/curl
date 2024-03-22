---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_STARTTRANSFER_TIME
Section: 3
Source: libcurl
See-also:
  - CURLINFO_STARTTRANSFER_TIME_T (3)
  - CURLOPT_TIMEOUT (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
---

# NAME

CURLINFO_STARTTRANSFER_TIME - get the time until the first byte is received

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_STARTTRANSFER_TIME,
                           double *timep);
~~~

# DESCRIPTION

Pass a pointer to a double to receive the time, in seconds, it took from the
start until the first byte is received by libcurl. This includes
CURLINFO_PRETRANSFER_TIME(3) and also the time the server needs to
calculate the result.

When a redirect is followed, the time from each request is added together.

See also the TIMES overview in the curl_easy_getinfo(3) man page.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    double start;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(CURLE_OK == res) {
      res = curl_easy_getinfo(curl, CURLINFO_STARTTRANSFER_TIME, &start);
      if(CURLE_OK == res) {
        printf("Time: %.1f", start);
      }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 7.9.2

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
