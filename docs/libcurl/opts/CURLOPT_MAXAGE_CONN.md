---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MAXAGE_CONN
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FORBID_REUSE (3)
  - CURLOPT_FRESH_CONNECT (3)
  - CURLOPT_MAXLIFETIME_CONN (3)
  - CURLOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.65.0
---

# NAME

CURLOPT_MAXAGE_CONN - max idle time allowed for reusing a connection

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MAXAGE_CONN, long age);
~~~

# DESCRIPTION

Pass a long as parameter containing *age* - the maximum time in seconds
allowed for an existing connection to have been idle to be considered for
reuse for this request.

The "connection cache" holds previously used connections. When a new request
is to be done, libcurl considers any connection that matches for reuse. The
CURLOPT_MAXAGE_CONN(3) limit prevents libcurl from trying too old
connections for reuse, since old connections have a higher risk of not working
and thus trying them is a performance loss and sometimes service loss due to
the difficulties to figure out the situation. If a connection is found in the
cache that is older than this set *age*, it is closed instead.

# DEFAULT

118 seconds

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* only allow 30 seconds idle time */
    curl_easy_setopt(curl, CURLOPT_MAXAGE_CONN, 30L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

curl_easy_setopt(3) returns a CURLcode indicating success or error.

CURLE_OK (0) means everything was OK, non-zero means an error occurred, see
libcurl-errors(3).
