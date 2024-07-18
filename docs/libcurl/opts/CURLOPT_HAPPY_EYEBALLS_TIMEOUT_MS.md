---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS
Section: 3
Source: libcurl
Protocol:
  - All
See-also:
  - CURLOPT_CONNECTTIMEOUT_MS (3)
  - CURLOPT_LOW_SPEED_LIMIT (3)
  - CURLOPT_TIMEOUT (3)
Added-in: 7.59.0
---

# NAME

CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS - head start for IPv6 for happy eyeballs

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS,
                          long timeout);
~~~

# DESCRIPTION

Happy eyeballs is an algorithm that attempts to connect to both IPv4 and IPv6
addresses for dual-stack hosts, preferring IPv6 first for *timeout*
milliseconds. If the IPv6 address cannot be connected to within that time then
a connection attempt is made to the IPv4 address in parallel. The first
connection to be established is the one that is used.

The range of suggested useful values for *timeout* is limited. Happy
Eyeballs RFC 6555 says "It is RECOMMENDED that connection attempts be paced
150-250 ms apart to balance human factors against network load." libcurl
currently defaults to 200 ms. Firefox and Chrome currently default to 300 ms.

# DEFAULT

CURL_HET_DEFAULT (currently defined as 200L)

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");
    curl_easy_setopt(curl, CURLOPT_HAPPY_EYEBALLS_TIMEOUT_MS, 300L);

    curl_easy_perform(curl);

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK
