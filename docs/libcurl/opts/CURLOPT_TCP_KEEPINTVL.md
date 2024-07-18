---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_TCP_KEEPINTVL
Section: 3
Source: libcurl
See-also:
  - CURLOPT_TCP_KEEPALIVE (3)
  - CURLOPT_TCP_KEEPIDLE (3)
  - CURLOPT_TCP_KEEPCNT (3)
Protocol:
  - TCP
Added-in: 7.25.0
---

# NAME

CURLOPT_TCP_KEEPINTVL - TCP keep-alive interval

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_TCP_KEEPINTVL, long interval);
~~~

# DESCRIPTION

Pass a long. Sets the interval, in seconds, to wait between sending keepalive
probes. Not all operating systems support this option. (Added in 7.25.0)

The maximum value this accepts is 2147483648. Any larger value is capped to
this amount.

# DEFAULT

60

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com");

    /* enable TCP keep-alive for this transfer */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);

    /* set keep-alive idle time to 120 seconds */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPIDLE, 120L);

    /* interval time between keep-alive probes: 60 seconds */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPINTVL, 60L);

    /* maximum number of keep-alive probes: 3 */
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPCNT, 3L);

    curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
