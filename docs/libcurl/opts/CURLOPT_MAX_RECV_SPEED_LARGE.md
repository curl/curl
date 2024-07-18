---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLOPT_MAX_RECV_SPEED_LARGE
Section: 3
Source: libcurl
See-also:
  - CURLOPT_LOW_SPEED_LIMIT (3)
  - CURLOPT_MAX_SEND_SPEED_LARGE (3)
  - CURLOPT_TIMEOUT (3)
Protocol:
  - All
Added-in: 7.15.5
---

# NAME

CURLOPT_MAX_RECV_SPEED_LARGE - rate limit data download speed

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLcode curl_easy_setopt(CURL *handle, CURLOPT_MAX_RECV_SPEED_LARGE,
                          curl_off_t maxspeed);
~~~

# DESCRIPTION

Pass a curl_off_t as parameter. If a download exceeds this *maxspeed*
(counted in bytes per second) the transfer pauses to keep the average speed
less than or equal to the parameter value. Defaults to unlimited speed.

This is not an exact science. libcurl attempts to keep the average speed below
the given threshold over a period time.

If you set *maxspeed* to a value lower than CURLOPT_BUFFERSIZE(3),
libcurl might download faster than the set limit initially.

This option does not affect transfer speeds done with FILE:// URLs.

# DEFAULT

0, disabled

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  CURL *curl = curl_easy_init();
  if(curl) {
    CURLcode ret;
    curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
    /* cap the download speed to 31415 bytes/sec */
    curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, (curl_off_t)31415);
    ret = curl_easy_perform(curl);
  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

Returns CURLE_OK if the option is supported, and CURLE_UNKNOWN_OPTION if not.
