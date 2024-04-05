---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MAXCONNECTS
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_MAXCONNECTS (3)
  - CURLMOPT_MAX_HOST_CONNECTIONS (3)
  - CURLMOPT_MAX_TOTAL_CONNECTIONS (3)
  - CURLOPT_MAXREDIRS (3)
Protocol:
  - All
---

# NAME

CURLOPT_MAXCONNECTS - maximum connection cache size

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MAXCONNECTS, long amount);
~~~

# DESCRIPTION

Pass a long. The set *amount* is the maximum number of simultaneously open
persistent connections that libcurl may cache in the pool associated with this
handle. The default is 5, and there is not much point in changing this value
unless you are perfectly aware of how this works. This concerns connections
using any of the protocols that support persistent connections.

When reaching the maximum limit, curl closes the oldest one in the cache to
prevent increasing the number of open connections.

If you already have performed transfers with this curl handle, setting a
smaller CURLOPT_MAXCONNECTS(3) than before may cause open connections to
get closed unnecessarily.

If you add this easy handle to a multi handle, this setting is not
acknowledged, and you must instead use curl_multi_setopt(3) and the
CURLMOPT_MAXCONNECTS(3) option.

# DEFAULT

5

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* limit the connection cache for this handle to no more than 3 */
    curl_easy_setopt(curl, CURLOPT_MAXCONNECTS, 3L);
    ret = curl_easy_perform(curl);
  }
}
~~~

# AVAILABILITY

Always

# RETURN VALUE

Returns CURLE_OK
