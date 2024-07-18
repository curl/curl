---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_TOTAL_TIME_T
Section: 3
Source: libcurl
See-also:
  - CURLINFO_TOTAL_TIME (3)
  - CURLOPT_TIMEOUT (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - All
Added-in: 7.61.0
---
# NAME

CURLINFO_TOTAL_TIME_T - get total time of previous transfer in microseconds

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_TOTAL_TIME_T,
                           curl_off_t *timep);
~~~

# DESCRIPTION

Pass a pointer to a curl_off_t to receive the total time in microseconds
for the previous transfer, including name resolving, TCP connect etc.
The curl_off_t represents the time in microseconds.

When a redirect is followed, the time from each request is added together.

See also the TIMES overview in the curl_easy_getinfo(3) man page.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;
    curl_off_t total;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    res = curl_easy_perform(curl);
    if(CURLE_OK == res) {
      res = curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME_T, &total);
      if(CURLE_OK == res) {
        printf("Time: %" CURL_FORMAT_CURL_OFF_T ".%06ld", total / 1000000,
               (long)(total % 1000000));
      }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
