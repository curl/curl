---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MAXLIFETIME_CONN
Section: 3
Source: libcurl
See-also:
  - CURLOPT_FORBID_REUSE (3)
  - CURLOPT_FRESH_CONNECT (3)
  - CURLOPT_MAXAGE_CONN (3)
  - CURLOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.80.0
---

# NAME

CURLOPT_MAXLIFETIME_CONN - max lifetime (since creation) allowed for reusing a connection

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MAXLIFETIME_CONN,
                          long maxlifetime);
~~~

# DESCRIPTION

Pass a long as parameter containing *maxlifetime* - the maximum time in
seconds, since the creation of the connection, that you allow an existing
connection to have to be considered for reuse for this request.

libcurl features a connection cache that holds previously used connections.
When a new request is to be done, libcurl considers any connection that
matches for reuse. The CURLOPT_MAXLIFETIME_CONN(3) limit prevents
libcurl from trying too old connections for reuse. This can be used for
client-side load balancing. If a connection is found in the cache that is
older than this set *maxlifetime*, it is instead marked for closure.

If set to 0, this behavior is disabled: all connections are eligible for reuse.

# DEFAULT

0 seconds (i.e., disabled)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* only allow each connection to be reused for 30 seconds */
    curl_easy_setopt(curl, CURLOPT_MAXLIFETIME_CONN, 30L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK.
