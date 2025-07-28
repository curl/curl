---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TIMECONDITION
Section: 3
Source: libcurl
See-also:
  - CURLINFO_FILETIME (3)
  - CURLOPT_TIMEVALUE (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

CURLOPT_TIMECONDITION - select condition for a time request

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TIMECONDITION, long cond);
~~~

# DESCRIPTION

Pass a long as parameter. This defines how the CURLOPT_TIMEVALUE(3) time
value is treated. You can set this parameter to *CURL_TIMECOND_IFMODSINCE*
or *CURL_TIMECOND_IFUNMODSINCE*.

The last modification time of a file is not always known and in such instances
this feature has no effect even if the given time condition would not have
been met. curl_easy_getinfo(3) with the *CURLINFO_CONDITION_UNMET*
option can be used after a transfer to learn if a zero-byte successful
"transfer" was due to this condition not matching.

# DEFAULT

CURL_TIMECOND_NONE (0)

# %PROTOCOLS%

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
    curl_easy_setopt(curl, CURLOPT_TIMECONDITION,
                     (long)CURL_TIMECOND_IFMODSINCE);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
