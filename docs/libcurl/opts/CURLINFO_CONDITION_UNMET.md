---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLINFO_CONDITION_UNMET
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TIMECONDITION (3)
  - CURLOPT_TIMEVALUE (3)
  - curl_easy_getinfo (3)
  - curl_easy_setopt (3)
Protocol:
  - HTTP
Added-in: 7.19.4
---

# NAME

CURLINFO_CONDITION_UNMET - get info on unmet time conditional or 304 HTTP response.

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_getinfo(CURL *handle, CURLINFO_CONDITION_UNMET,
                           long *unmet);
~~~

# DESCRIPTION

Pass a pointer to a long to receive the number 1 if the condition provided in
the previous request did not match (see CURLOPT_TIMECONDITION(3)). Alas,
if this returns a 1 you know that the reason you did not get data in return is
because it did not fulfill the condition. The long this argument points to
gets a zero stored if the condition instead was met. This can also return 1 if
the server responded with a 304 HTTP status code, for example after sending a
custom "If-Match-*" header.

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode res;

    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* January 1, 2020 is 1577833200 */
    curl_easy_setopt(curl, CURLOPT_TIMEVALUE, 1577833200L);

    /* If-Modified-Since the above time stamp */
    curl_easy_setopt(curl, CURLOPT_TIMECONDITION,
                     (long)CURL_TIMECOND_IFMODSINCE);

    /* Perform the request */
    res = curl_easy_perform(curl);

    if(!res) {
      /* check the time condition */
      long unmet;
      res = curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &unmet);
      if(!res) {
        printf("The time condition was %sfulfilled\n", unmet?"NOT":"");
      }
    }
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_getinfo(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
