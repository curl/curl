---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TIMEVALUE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TIMECONDITION (3)
  - CURLOPT_TIMEVALUE_LARGE (3)
Protocol:
  - HTTP
---

# NAME

CURLOPT_TIMEVALUE - time value for conditional

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TIMEVALUE, long val);
~~~

# DESCRIPTION

Pass a long *val* as parameter. This should be the time counted as seconds
since 1 Jan 1970, and the time is used in a condition as specified with
CURLOPT_TIMECONDITION(3).

On systems with 32 bit 'long' variables (such as Windows), this option cannot
set dates beyond the year 2038. Consider CURLOPT_TIMEVALUE_LARGE(3)
instead.

# DEFAULT

0

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* January 1, 2020 is 1577833200 */
    curl_easy_setopt(curl, CURLOPT_TIMEVALUE, 1577833200L);

    /* If-Modified-Since the above time stamp */
    curl_easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
