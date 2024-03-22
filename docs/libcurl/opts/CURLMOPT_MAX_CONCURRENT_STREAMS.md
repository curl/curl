---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Title: CURLMOPT_MAX_CONCURRENT_STREAMS
Section: 3
Source: libcurl
See-also:
  - CURLMOPT_MAXCONNECTS (3)
  - CURLOPT_MAXCONNECTS (3)
Protocol:
  - HTTP
---

# NAME

CURLMOPT_MAX_CONCURRENT_STREAMS - max concurrent streams for http2

# SYNOPSIS

~~~c
#include <curl/curl.h>

CURLMcode curl_multi_setopt(CURLM *handle, CURLMOPT_MAX_CONCURRENT_STREAMS,
                            long max);
~~~

# DESCRIPTION

Pass a long indicating the **max**. The set number is used as the maximum
number of concurrent streams libcurl should support on connections done using
HTTP/2 or HTTP/3.

Valid values range from 1 to 2147483647 (2^31 - 1) and defaults to 100. The
value passed here would be honored based on other system resources properties.

# DEFAULT

100

# EXAMPLE

~~~c
int main(void)
{
  CURLM *m = curl_multi_init();
  /* max concurrent streams 200 */
  curl_multi_setopt(m, CURLMOPT_MAX_CONCURRENT_STREAMS, 200L);
}
~~~

# AVAILABILITY

Added in 7.67.0

# RETURN VALUE

Returns CURLM_OK if the option is supported, and CURLM_UNKNOWN_OPTION if not.
