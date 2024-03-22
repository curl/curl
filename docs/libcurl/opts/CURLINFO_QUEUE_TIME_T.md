---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_QUEUE_TIME_T
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

CURLINFO_QUEUE_TIME_T - time this transfer was queued

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_QUEUE_TIME_T,
                           curl_off_t *timep);
~~~

# DESCRIPTION

Pass a pointer to a curl_off_t to receive the time, in microseconds, this
transfer was held in a waiting queue before it started "for real". A transfer
might be put in a queue if after getting started, it cannot create a new
connection etc due to set conditions and limits imposed by the application.

See also the TIMES overview in the curl_easy_getinfo(3) man page.

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_off_t queue;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(CURLE_OK == res) {
      res = curl_easy_getinfo(curl, CURLINFO_QUEUE_TIME_T, &queue);
      if(CURLE_OK == res) {
        printf("Queued: %" CURL_FORMAT_CURL_OFF_T ".%06ld us", queue / 1000000,
               (long)(queue % 1000000));
      }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# AVAILABILITY

Added in 8.6.0

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
