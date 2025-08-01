---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TIMEVALUE_LARGE
Section: 3
Source: libcurl
See-also:
  - CURLINFO_FILETIME (3)
  - CURLOPT_TIMECONDITION (3)
  - CURLOPT_TIMEVALUE (3)
Protocol:
  - HTTP
Added-in: 7.59.0
---

# NAME

CURLOPT_TIMEVALUE_LARGE - time value for conditional

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TIMEVALUE_LARGE,
                          curl_off_t val);
~~~

# DESCRIPTION

Pass a curl_off_t *val* as parameter. This should be the time counted as
seconds since 1 Jan 1970, and the time is used in a condition as specified
with CURLOPT_TIMECONDITION(3).

The difference between this option and CURLOPT_TIMEVALUE(3) is the type of the
argument. On systems where 'long' is only 32 bits wide, this option has to be
used to set dates beyond the year 2038.

# DEFAULT

0

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* January 1, 2020 is 1577833200 */
    curl_easy_setopt(curl, CURLOPT_TIMEVALUE_LARGE, (curl_off_t)1577833200);

    /* If-Modified-Since the above time stamp */
    curl_easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);

    /* Perform the request */
    curl_easy_perform(curl);
  }
}
~~~

# HISTORY

**CURL_TIMECOND_*** enums became `long` types in 8.13.0, prior to this version
a `long` cast was necessary when passed to curl_easy_setopt(3).

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
