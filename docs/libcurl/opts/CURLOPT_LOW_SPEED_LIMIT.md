---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_LOW_SPEED_LIMIT
Section: 3
Source: libcurl
See-also:
  - CURLOPT_LOW_SPEED_TIME (3)
  - CURLOPT_MAX_RECV_SPEED_LARGE (3)
  - CURLOPT_MAX_SEND_SPEED_LARGE (3)
  - CURLOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

CURLOPT_LOW_SPEED_LIMIT - low speed limit in bytes per second

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_LOW_SPEED_LIMIT,
                          long speedlimit);
~~~

# DESCRIPTION

Pass a long as parameter. It contains the average transfer speed in bytes per
second that the transfer should be below during
CURLOPT_LOW_SPEED_TIME(3) seconds for libcurl to consider it to be too
slow and abort.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    /* abort if slower than 30 bytes/sec during 60 seconds */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 30L);
    res = curl_easy_perform(curl);
    if(CURLE_OPERATION_TIMEDOUT == res) {
      printf("Timeout!\n");
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK
