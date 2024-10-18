---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_LOW_SPEED_TIME
Section: 3
Source: libcurl
See-also:
  - CURLOPT_LOW_SPEED_LIMIT (3)
  - CURLOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.1
---

# NAME

CURLOPT_LOW_SPEED_TIME - low speed limit time period

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_LOW_SPEED_TIME,
                          long speedtime);
~~~

# DESCRIPTION

Pass a long as parameter. It contains the time in number seconds that the
transfer speed should be below the CURLOPT_LOW_SPEED_LIMIT(3) for the
library to consider it too slow and abort.

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
      printf("Timeout.\n");
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK
